"""Leased AWS group operations. Checkpoint intent before every remote mutation."""

import json
import logging
import uuid
from datetime import timedelta

from botocore.exceptions import ClientError
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import object_session

from .account_dispatcher import (
    group_scope,
    run_fenced,
)
from .aws import AwsFailure, AwsGateway
from .config import settings
from .database import SessionLocal
from .models import (
    AwsAccount,
    GroupJob,
    ManagedGroup,
    StopSchedule,
    Subscription,
    User,
    now,
)
from .security import audit
from .worker_guards import attempt_config, check_config
from .automatic_retries import (
    provisioning_stopped, ready_clause, retry_config, retry_view, schedule_retry, settle_retry,
)
from .retry_policy import classify_failure

logger = logging.getLogger("kiro.groups")
PENDING_STATES = ("queued", "running", "needs_review")


def job_view(job, db=None):
    result = {
        key: getattr(job, key)
        for key in (
            "id",
            "group_id",
            "record_id",
            "kind",
            "state",
            "phase",
            "attempts",
            "error",
            "created_at",
            "finished_at",
        )
    }
    active = job.state in ("queued", "running")
    db = db or object_session(job)
    if db is not None:
        return result | retry_view(db, "group", job.id, active=active, state=job.state)
    with SessionLocal() as db:
        return result | retry_view(db, "group", job.id, active=active, state=job.state)


def claim_group_job(*, account_id=None):
    with SessionLocal() as db:
        eligible = or_(
            GroupJob.state == "queued",
            and_(GroupJob.state == "running", GroupJob.lease_until < now()),
        )
        eligible = and_(eligible, select(ManagedGroup.id).where(
            ManagedGroup.id == GroupJob.group_id,
            ManagedGroup.active_job_id == GroupJob.id,
        ).exists())
        eligible = and_(eligible, ready_clause("group", GroupJob.id))
        if account_id is not None:
            eligible = and_(eligible, group_scope(GroupJob.group_id, account_id))
        jid = db.scalar(
            select(GroupJob.id).where(eligible).order_by(GroupJob.created_at).limit(1)
        )
        if not jid:
            return None
        token = str(uuid.uuid4())
        changed = db.execute(
            update(GroupJob)
            .where(GroupJob.id == jid, eligible)
            .values(
                state="running",
                lease_token=token,
                lease_until=now() + timedelta(seconds=settings.worker_lease_seconds),
                attempts=GroupJob.attempts + 1,
            )
        )
        if changed.rowcount:
            from .group_member_batches import batch_for_job, sync_batch
            batch = batch_for_job(db, jid)
            if batch:
                sync_batch(db, batch, db.get(ManagedGroup, batch.group_id))
        db.commit()
        return (jid, token) if changed.rowcount else None


def locked(db, jid, token):
    changed = db.execute(
        update(GroupJob)
        .where(
            GroupJob.id == jid,
            GroupJob.state == "running",
            GroupJob.lease_token == token,
        )
        .values(lease_until=now() + timedelta(seconds=settings.worker_lease_seconds))
    )
    if not changed.rowcount:
        raise RuntimeError("分组任务租约已失效")
    job = db.get(GroupJob, jid)
    group = db.get(ManagedGroup, job.group_id)
    if group.active_job_id != job.id:
        raise RuntimeError("分组任务已被替换")
    return job, group


def checkpoint(jid, token, frozen_config=None):
    with SessionLocal() as db:
        job, group = locked(db, jid, token)
        from .provisioning_coordinator import job_guard
        job_guard(db, job)
        from .group_members import group_authorized, member_context
        if not group_authorized(db, db.get(User, job.actor_id), group, job.kind):
            raise AwsFailure("分组所有者、操作者或 AWS 绑定已停用")
        if job.record_id:
            member_context(db, job, group)
        if job.kind == "attach":
            from .group_subscription_state import checkpoint_join
            checkpoint_join(db, job.record_id)
        payload = json.loads(job.payload)
        if frozen_config is not None:
            check_config(db, db.get(AwsAccount, group.aws_account_id), frozen_config)
            payload["worker_config_hash"] = frozen_config
            job.payload = json.dumps(payload)
        if job.kind == "detach" and payload.get("native_activation_id"):
            from .group_subscription_state import detach_context
            detach_context(db, db.get(Subscription, job.record_id), payload, job.id, job.actor_id)
        job.phase = "pending"
        db.commit()


def complete(jid, token, membership_id=None, observation=None, **values):
    with SessionLocal() as db:
        job, group = locked(db, jid, token)
        settle_retry(db, "group", jid)
        for key, value in values.items():
            setattr(group, key, value)
        group.state = "deleted" if group.deleted_at else "ready"
        group.active_job_id = group.error = None
        group.updated_at = now()
        if job.kind in ("rename", "delete"):
            group.revision += 1
        if job.record_id:
            record = db.get(Subscription, job.record_id)
            if record.active_operation_id != job.id or record.group_id != group.id:
                raise RuntimeError("成员任务已被替换")
            record.group_membership_id = membership_id
            record.active_operation_id = None
            record.updated_at = now()
            from .group_subscription_state import detach_member, finish_join
            if job.kind == "attach":
                finish_join(db, record, observation)
            if observation:
                from .subscription_sources import apply_observation
                apply_observation(record, observation)
            if job.kind == "detach":
                detach_member(db, record)
                record.group_id = None
                schedule = db.get(StopSchedule, record.id)
                if schedule and schedule.source_group_id == group.id:
                    # Keep the already authorized individual deadline after moving out.
                    schedule.source_group_id = schedule.source_group_revision = None
                    schedule.individual_override = True
        job.state, job.phase, job.finished_at = "completed", "done", now()
        job.error = job.lease_token = job.lease_until = None
        audit(
            db,
            db.get(User, job.actor_id),
            f"group_{job.kind}_completed",
            f"AWS 分组操作完成：{group.name}",
            subject=group.owner_id,
        )
        from .group_member_batches import advance_batch
        advance_batch(db, job, group)
        db.commit()


def fail(jid, token, message, uncertain, release_remote=False, *, error=None, frozen_config=None):
    with SessionLocal() as db:
        job, group = locked(db, jid, token)
        if (error is not None and frozen_config is not None and not release_remote
                and schedule_retry(db, "group", jid, error,
                                   mode="reconcile" if uncertain else "retry",
                                   config_hash=frozen_config,
                                   stopped=provisioning_stopped(db, "group", job))):
            job.state, job.error, group.error = "queued", message, message
            job.lease_token = job.lease_until = None
            if not uncertain:
                job.phase = "ready"
            from .group_member_batches import batch_for_job, sync_batch
            batch = batch_for_job(db, job.id)
            if batch:
                sync_batch(db, batch, group)
            db.commit()
            return
        settle_retry(db, "group", jid)
        job.state = group.state = "needs_review" if uncertain else "failed"
        job.error = group.error = message
        job.lease_token = job.lease_until = None
        # Preserve a pending intent, including on credential/proxy failures.
        if not uncertain:
            job.phase = "ready"
            payload = json.loads(job.payload)
            payload.pop("worker_config_hash", None)
            job.payload = json.dumps(payload)
        if job.record_id and job.kind == "attach":
            from .group_subscription_state import fail_join
            fail_join(db, db.get(Subscription, job.record_id), uncertain)
        if release_remote:
            group.remote_id = None
        group.updated_at = now()
        audit(
            db,
            db.get(User, job.actor_id),
            f"group_{job.kind}_{job.state}",
            f"AWS 分组操作：{group.name}；{message}",
            subject=group.owner_id,
        )
        from .group_member_batches import batch_for_job, sync_batch
        batch = batch_for_job(db, job.id)
        if batch:
            sync_batch(db, batch, group)
        db.commit()


def run_group_job(gateway_factory=None, *, account_id=None):
    return run_fenced(account_id, ("group",),
                      lambda aid: _run_one(gateway_factory or AwsGateway, aid))


def _run_one(gateway_factory, account_id):
    claimed = claim_group_job(account_id=account_id)
    if not claimed:
        return False
    jid, token = claimed
    pending = False
    recovering_write = False
    frozen_config = None
    try:
        with SessionLocal() as db:
            job = db.get(GroupJob, jid)
            pending = job.phase == "pending"
            recovering_write = pending
            group = db.get(ManagedGroup, job.group_id)
            account = db.get(AwsAccount, group.aws_account_id)
            from .provisioning_coordinator import job_guard
            job_guard(db, job, recovering=pending)
            actor = db.get(User, job.actor_id)
            from .group_members import group_authorized, member_context
            authorized = group_authorized(db, actor, group, job.kind)
            payload = json.loads(job.payload)
            frozen_config = attempt_config(db, account, payload.get("worker_config_hash")
                                           if pending else retry_config(db, "group", jid))
            record = db.get(Subscription, job.record_id) if job.record_id else None
            if job.record_id:
                member_context(db, job, group, recovering=pending)
            native_activation = None
            if job.kind == "detach" and payload.get("native_activation_id"):
                from .group_subscription_state import detach_context
                _, native_activation = detach_context(
                    db, record, payload, job.id, job.actor_id, recovering=pending,
                )
            db.expunge_all()
        gateway = gateway_factory(account)
        if job.kind == "create" or (job.kind == "rename" and not group.remote_id):
            remote_id = gateway.get_group_id(payload["name"])
            remote = gateway.get_group(remote_id) if remote_id else None
            if remote:
                if remote["description"] != group.marker:
                    # An earlier create may still exist under another name.
                    # A foreign lookup result cannot resolve that pending intent.
                    raise AwsFailure("AWS 同名分组不属于本次创建请求，不能接管")
            else:
                if pending:
                    raise AwsFailure("分组创建结果尚未确认，请稍后重试核对")
                if not authorized:
                    raise AwsFailure("分组所有者、操作者或 AWS 绑定已停用")
                checkpoint(jid, token, frozen_config)
                pending = True
                try:
                    remote_id = gateway.create_group(payload["name"], group.marker)
                except ClientError as exc:
                    # Only a rejection of this fresh write proves it did not
                    # apply. Lookup failures cannot resolve an older intent.
                    metadata = exc.response.get("ResponseMetadata", {})
                    if (
                        400 <= metadata.get("HTTPStatusCode", 0) < 500
                        and not metadata.get("RetryAttempts", 0)
                        and exc.response.get("Error", {}).get("Code")
                        in {
                            "ValidationException",
                            "AccessDeniedException",
                            "ResourceNotFoundException",
                            "ServiceQuotaExceededException",
                            "ThrottlingException",
                            "ConflictException",
                        }
                    ):
                        pending = False
                    raise
                remote = gateway.get_group(remote_id)
                if not remote or remote["description"] != group.marker:
                    raise AwsFailure("分组创建结果尚未确认", uncertain=True)
            complete(jid, token, remote_id=remote_id, name=payload["name"])
        elif job.kind == "link":
            if not authorized:
                raise AwsFailure("分组所有者、操作者或 AWS 绑定已停用")
            remote = gateway.get_group(payload["remote_id"])
            if not remote:
                raise AwsFailure("AWS 分组不存在")
            with SessionLocal() as db:
                managed = db.scalar(
                    select(ManagedGroup.id)
                    .where(
                        ManagedGroup.aws_scope == group.aws_scope,
                        ManagedGroup.id != group.id,
                        or_(
                            ManagedGroup.marker == remote["description"],
                            ManagedGroup.remote_id == remote["id"],
                        ),
                    )
                    .limit(1)
                )
            if managed:
                fail(
                    jid,
                    token,
                    "该 AWS 分组属于其他已保存的管理请求，不能接管",
                    False,
                    release_remote=True,
                )
                return True
            complete(jid, token, name=remote["name"], remote_id=remote["id"])
        elif job.kind == "rename":
            remote = gateway.get_group(group.remote_id)
            if not remote:
                raise AwsFailure("AWS 分组不存在")
            if remote["name"] != payload["name"]:
                if pending:
                    raise AwsFailure("分组名称尚未确认，只可只读核对，不能重复发送", uncertain=True)
                if not authorized:
                    raise AwsFailure("分组所有者、操作者或 AWS 绑定已停用")
                checkpoint(jid, token, frozen_config)
                pending = True
                gateway.update_group(group.remote_id, payload["name"])
                remote = gateway.get_group(group.remote_id)
                if not remote or remote["name"] != payload["name"]:
                    raise AwsFailure("分组名称尚未确认", uncertain=True)
            complete(jid, token, name=payload["name"])
        elif job.kind == "delete":
            remote = gateway.get_group(group.remote_id) if group.remote_id else None
            if remote:
                if pending:
                    raise AwsFailure("分组删除尚未确认，只可只读核对，不能重复发送", uncertain=True)
                if not authorized:
                    raise AwsFailure("分组所有者、操作者或 AWS 绑定已停用")
                if gateway.list_group_memberships(group.remote_id):
                    pending = False
                    raise AwsFailure("AWS 分组仍有成员，不能删除")
                checkpoint(jid, token, frozen_config)
                pending = True
                gateway.delete_group(group.remote_id)
                if gateway.get_group(group.remote_id):
                    raise AwsFailure("分组删除结果尚未确认", uncertain=True)
            complete(jid, token, deleted_at=now())
        elif job.kind in ("attach", "detach"):
            if not authorized and not pending:
                raise AwsFailure("分组所有者、操作者或 AWS 绑定已停用")
            if record.active_operation_id != job.id or record.group_id != group.id:
                raise AwsFailure("成员操作已变化")
            if job.kind == "attach":
                from .group_subscription_state import check_join
                native_join = check_join(record.id, group.id, gateway, recovering=pending)
            membership_id = gateway.get_group_membership(
                group.remote_id, record.sso_user_id
            )
            if job.kind == "attach" and not membership_id:
                if pending:
                    raise AwsFailure("AWS 成员加入结果尚未确认，不能重复发送", uncertain=True)
                checkpoint(jid, token, frozen_config)
                pending = True
                gateway.create_group_membership(group.remote_id, record.sso_user_id)
                membership_id = gateway.get_group_membership(
                    group.remote_id, record.sso_user_id
                )
                if not membership_id:
                    raise AwsFailure("AWS 分组成员尚未确认", uncertain=True)
            elif job.kind == "detach" and membership_id:
                if native_activation:
                    from .group_subscription_state import verify_member_sources
                    verify_member_sources(gateway, record, group, native_activation.subscription_type)
                if pending:
                    raise AwsFailure("AWS 成员移出結果尚未确认，不能重复发送", uncertain=True)
                checkpoint(jid, token, frozen_config)
                pending = True
                gateway.delete_group_membership(membership_id)
                membership_id = gateway.get_group_membership(
                    group.remote_id, record.sso_user_id
                )
                if membership_id:
                    raise AwsFailure("AWS 分组成员移出尚未确认", uncertain=True)
            if job.kind == "attach":
                check_join(record.id, group.id, gateway, recovering=True)
            elif native_activation:
                from .group_subscription_state import verify_member_sources
                verify_member_sources(gateway, record, group, present=False)
            observation = None
            if (job.kind == "attach" and native_join) or native_activation:
                from .subscription_sources import observe_subscription
                observation = observe_subscription(gateway, record)
            complete(jid, token, membership_id=membership_id, observation=observation)
        else:
            raise AwsFailure("不支持的分组操作")
    except AwsFailure as exc:
        if not recovering_write and classify_failure(exc).proven_unsent:
            pending = False
        fail(jid, token, str(exc), pending or exc.uncertain,
             error=exc, frozen_config=frozen_config)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if not recovering_write and classify_failure(exc).proven_unsent:
            pending = False
        fail(jid, token, f"AWS 分组操作失败：{code}", pending,
             error=exc, frozen_config=frozen_config)
    except Exception as exc:
        logger.error("Group job %s failed: %s", jid, type(exc).__name__)
        try:
            fail(
                jid, token, f"分组操作中断（{type(exc).__name__}），请重试核对",
                pending and (recovering_write or not classify_failure(exc).proven_unsent),
                error=exc, frozen_config=frozen_config,
            )
        except Exception:
            logger.error("Group job %s remains leased for safe recovery", jid)
    return True
