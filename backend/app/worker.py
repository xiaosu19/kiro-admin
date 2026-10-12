"""Durable single-host queue; remote subscription writes are never blindly replayed."""

import logging
import signal
import uuid
from contextlib import nullcontext
from datetime import timedelta

from botocore.exceptions import ClientError
from sqlalchemy import and_, or_, select, update

from .account_dispatcher import (
    AccountDispatcher, account_fence, candidate_accounts, resource_fence,
)
from .aws import AwsFailure, AwsGateway
from .batches import update_batch_item
from .config import settings
from .database import SessionLocal
from .group_jobs import run_group_job
from .lifecycle import run_operation
from .models import (
    AwsAccount,
    Batch,
    Binding,
    ManagedGroup,
    NativeGroupGrant,
    Plan,
    PlanCounter,
    Subscription,
    User,
    now,
)
from .plan_change_worker import reconcile_due, run_plan_change
from .schedules import activate_after_subscription, enqueue_due, ensure_not_expired
from .security import audit, encrypt
from .worker_guards import attempt_config, check_config, check_provisioning
from .automatic_retries import (
    provisioning_stopped, ready_clause, retry_config, schedule_retry, settle_retry,
)
from .retry_policy import classify_failure

logger = logging.getLogger("kiro.worker")
PENDING_STEPS = ("create_user_pending", "password_pending", "subscribe_pending", "group_membership_pending",
                 "group_entitlement_pending")
CREDENTIAL_STEPS = ("create_user", "create_user_pending", "password", "password_pending")


def eligible_records(*, account_id=None, record_id=None):
    eligible = or_(
        Subscription.state == "queued",
        and_(Subscription.state == "running", Subscription.lease_until < now()),
    )
    eligible = and_(
        eligible,
        or_(
            Subscription.group_id.is_(None),
            Subscription.step.in_(("subscribe_pending", "group_entitlement_pending")),
            Subscription.group_id.in_(
                select(ManagedGroup.id).where(ManagedGroup.state == "ready")
            ),
        ),
    )
    eligible = and_(eligible, or_(
        Subscription.group_id.is_(None),
        Subscription.step.in_(CREDENTIAL_STEPS),
        Subscription.step == "group_entitlement_pending",
        ~Subscription.group_id.in_(select(NativeGroupGrant.group_id).where(
            NativeGroupGrant.state.in_(("active", "cancel_scheduled", "needs_review", "pending")))),
        select(ManagedGroup.id).where(
            ManagedGroup.id == Subscription.group_id,
            or_(ManagedGroup.active_job_id.is_(None), ManagedGroup.active_job_id == Subscription.id),
        ).exists(),
    ))
    eligible = and_(eligible, ready_clause("sso", Subscription.id))
    if account_id is not None:
        eligible = and_(eligible, Subscription.aws_account_id == account_id)
    if record_id is not None:
        eligible = and_(eligible, Subscription.id == record_id)
    return eligible


def candidate_records(*, account_id=None, record_id=None):
    with SessionLocal() as db:
        return list(db.execute(select(Subscription.aws_account_id, Subscription.id)
            .where(eligible_records(account_id=account_id, record_id=record_id))
            .order_by(Subscription.created_at)))


def claim(*, account_id=None, record_id=None):
    with SessionLocal() as db:
        eligible = eligible_records(account_id=account_id, record_id=record_id)
        record_id = db.scalar(
            select(Subscription.id)
            .where(eligible)
            .order_by(Subscription.created_at)
            .limit(1)
        )
        if not record_id:
            return None
        token = str(uuid.uuid4())
        changed = db.execute(
            update(Subscription)
            .where(Subscription.id == record_id, eligible)
            .values(
                state="running",
                lease_token=token,
                lease_until=now() + timedelta(seconds=settings.worker_lease_seconds),
                updated_at=now(),
                attempts=Subscription.attempts + 1,
            )
        )
        if changed.rowcount:
            record = db.get(Subscription, record_id)
            from .group_subscription_state import member_activation
            if (record.group_id and record.step not in (*CREDENTIAL_STEPS, "group_entitlement_pending")
                    and member_activation(db, record.id)):
                group_lock = db.execute(update(ManagedGroup).where(
                    ManagedGroup.id == record.group_id,
                    or_(ManagedGroup.active_job_id.is_(None), ManagedGroup.active_job_id == record_id),
                ).values(active_job_id=record_id))
                if not group_lock.rowcount:
                    db.rollback()
                    return None
            update_batch_item(db, record, "running")
        db.commit()
        return (record_id, token) if changed.rowcount else None


def load(db, record_id, token):
    r = db.get(Subscription, record_id)
    if not r or r.lease_token != token or r.state != "running":
        raise RuntimeError("任务租约已被其他进程接管")
    return r


def save(record_id, token, *, check_native_creation=False, frozen_config=None, **values):
    with SessionLocal() as db:
        changed = db.execute(
            update(Subscription)
            .where(
                Subscription.id == record_id,
                Subscription.lease_token == token,
                Subscription.state == "running",
            )
            .values({"updated_at": now(),
                     "lease_until": now() + timedelta(seconds=settings.worker_lease_seconds),
                     **values})
        )
        if not changed.rowcount:
            raise RuntimeError("任务租约已失效")
        if frozen_config is not None:
            r = load(db, record_id, token)
            check_provisioning(db, r, db.get(AwsAccount, r.aws_account_id), frozen_config)
            if values.get("step") in PENDING_STEPS:
                r.worker_config_hash = frozen_config
        if check_native_creation or values.get("step") == "group_membership_pending":
            from .group_subscription_state import checkpoint_join
            checkpoint_join(db, record_id, mark_intent=not check_native_creation,
                            preparing_credentials=check_native_creation)
        db.commit()


def sync_numbered_items(db, record):
    """Persist late child facts without waking admission or changing its state."""
    from .models import ProvisioningAccountBatch, ProvisioningItem
    from .provisioning_coordinator import sync_items

    item = db.get(ProvisioningItem, record.id)
    if item:
        db.flush()
        sync_items(db, db.get(ProvisioningAccountBatch, item.account_batch_id))


def finish(record_id, token, request_id=None):
    with SessionLocal() as db:
        r = load(db, record_id, token)
        settle_retry(db, "sso", record_id)
        subscribed_at = now()
        changed = db.execute(
            update(Subscription)
            .where(
                Subscription.id == record_id,
                Subscription.lease_token == token,
                Subscription.counted.is_(False),
            )
            .values(
                counted=True,
                state="completed",
                step="done",
                reserved=False,
                error=None,
                subscribed_at=subscribed_at,
                subscription_status="active",
                observed_subscription_type=r.subscription_type,
                updated_at=now(),
                aws_request_id=request_id,
                lease_until=None,
                lease_token=None,
            )
        )
        if not changed.rowcount:
            return
        if r.counter_id:
            result = db.execute(
                update(PlanCounter)
                .where(
                    PlanCounter.id == r.counter_id,
                    PlanCounter.cycle_number == r.cycle_number,
                    PlanCounter.pending_count > 0,
                )
                .values(
                    pending_count=PlanCounter.pending_count - 1,
                    used_count=PlanCounter.used_count + 1,
                    lifetime_count=PlanCounter.lifetime_count + 1,
                )
            )
            if not result.rowcount:
                raise RuntimeError("订阅计数与任务预占不一致，需要核对")
        audit(
            db,
            None,
            "subscription_completed",
            f"订阅开通成功：{r.username}",
            subject=r.owner_id,
        )
        update_batch_item(db, r, "completed")
        activate_after_subscription(db, r, subscribed_at)
        sync_numbered_items(db, r)
        db.commit()


def fail(record_id, token, message, uncertain=False, *, error=None, frozen_config=None):
    with SessionLocal() as db:
        r = load(db, record_id, token)
        # A rejected read says nothing about the membership write already proved
        # by this durable checkpoint. Never reset its intent or release its quota.
        uncertain = uncertain or r.step == "group_entitlement_pending"
        can_reconcile = uncertain and r.step != "password_pending"
        if error is not None and frozen_config is not None and (not uncertain or can_reconcile):
            if schedule_retry(db, "sso", record_id, error,
                              mode="reconcile" if uncertain else "retry",
                              config_hash=frozen_config,
                              stopped=provisioning_stopped(db, "sso", r)):
                if not uncertain and r.step in PENDING_STEPS:
                    if r.step == "password_pending":
                        r.credential_state = "one_time"
                    r.step = r.step.removesuffix("_pending")
                r.state, r.error, r.updated_at = "queued", message, now()
                r.lease_token = r.lease_until = None
                update_batch_item(db, r, "queued", message)
                sync_numbered_items(db, r)
                db.commit()
                return
        settle_retry(db, "sso", record_id)
        reserved = r.reserved
        if not uncertain and reserved:
            result = db.execute(
                update(PlanCounter)
                .where(
                    PlanCounter.id == r.counter_id,
                    PlanCounter.cycle_number == r.cycle_number,
                    PlanCounter.pending_count > 0,
                )
                .values(pending_count=PlanCounter.pending_count - 1)
            )
            if not result.rowcount:
                raise RuntimeError("处理中次数不一致")
            r.reserved = False
        from .group_subscription_state import fail_join
        fail_join(db, r, uncertain)
        if not uncertain and r.group_id:
            group = db.get(ManagedGroup, r.group_id)
            if group.active_job_id == r.id:
                group.active_job_id = None
        r.state = "needs_review" if uncertain else "failed"
        if not uncertain:
            # Explicit retry of a proved-unsent/rejected write can freeze a fresh
            # attempt. Uncertain sends keep the original hash across restarts.
            r.worker_config_hash = None
        update_batch_item(db, r, r.state, message)
        r.error = message
        r.updated_at = now()
        r.lease_token = None
        r.lease_until = None
        if not uncertain and r.step in ("create_user_pending", "password_pending", "subscribe_pending"):
            if r.step == "password_pending":
                r.credential_state = "one_time"
            r.step = r.step.removesuffix("_pending")
        audit(
            db,
            None,
            "subscription_needs_review" if uncertain else "subscription_failed",
            f"{r.username}：{message}",
            subject=r.owner_id,
        )
        sync_numbered_items(db, r)
        db.commit()


def finish_sso(record_id, token, observation=None):
    with SessionLocal() as db:
        r = load(db, record_id, token)
        if r.step == "group_entitlement_pending":
            from .group_subscription_state import entitlement_context
            entitlement_context(db, r)
        settle_retry(db, "sso", record_id)
        changed = db.execute(
            update(Subscription)
            .where(
                Subscription.id == record_id,
                Subscription.state == "running",
                Subscription.lease_token == token,
            )
            .values(
                state="completed",
                step="sso_ready",
                reserved=False,
                error=None,
                lease_token=None,
                lease_until=None,
                updated_at=now(),
            )
        )
        if not changed.rowcount:
            raise RuntimeError("任务租约已失效")
        from .group_subscription_state import finish_join
        finish_join(db, r, observation)
        if r.group_id:
            group = db.get(ManagedGroup, r.group_id)
            if group.active_job_id == r.id:
                group.active_job_id = None
        update_batch_item(db, r, "completed")
        audit(
            db, None, "sso_created", f"SSO 创建成功：{r.username}", subject=r.owner_id
        )
        sync_numbered_items(db, r)
        db.commit()


def run_one(gateway_factory=None, *, account_id=None, record_id=None):
    for aid, rid in candidate_records(account_id=account_id, record_id=record_id):
        with account_fence(aid, shared=True) as account:
            if not account:
                continue
            with resource_fence("record", rid) as acquired:
                if acquired and _run_one(gateway_factory or AwsGateway, aid, rid):
                    return True
    return False


def membership_lock(record_id, token, frozen_config):
    """Reserve the group only when credentials are ready for a native join."""
    from .group_subscription_state import join_context, member_activation

    with SessionLocal() as db:
        r = load(db, record_id, token)
        if not member_activation(db, record_id):
            return True
        account = db.get(AwsAccount, r.aws_account_id)
        if r.step == "group_membership_pending":
            check_config(db, account, frozen_config)
        else:
            check_provisioning(db, r, account, frozen_config)
        changed = db.execute(update(ManagedGroup).where(
            ManagedGroup.id == r.group_id, ManagedGroup.state == "ready",
            or_(ManagedGroup.active_job_id.is_(None), ManagedGroup.active_job_id == record_id),
        ).values(active_job_id=record_id))
        if not changed.rowcount:
            db.rollback()
            return False
        join_context(db, r, db.get(ManagedGroup, r.group_id),
                     recovering=r.step == "group_membership_pending")
        db.commit()
        return True


def await_group_entitlement(record_id, token, membership_id, frozen_config):
    """Atomically checkpoint a proved membership and release only its write lock."""
    from .group_subscription_state import entitlement_context, join_context

    with SessionLocal() as db:
        changed = db.execute(update(Subscription).where(
            Subscription.id == record_id, Subscription.state == "running", Subscription.lease_token == token,
        ).values(updated_at=now(), lease_until=now() + timedelta(seconds=settings.worker_lease_seconds)))
        if not changed.rowcount:
            raise RuntimeError("任务租约已失效")
        record = load(db, record_id, token)
        group = db.get(ManagedGroup, record.group_id)
        check_config(db, db.get(AwsAccount, record.aws_account_id), frozen_config)
        join_context(db, record, group, recovering=True)
        if not membership_id:
            raise RuntimeError("缺少已确认的 AWS 成员身份")
        released = db.execute(update(ManagedGroup).where(
            ManagedGroup.id == group.id, ManagedGroup.active_job_id == record.id,
        ).values(active_job_id=None))
        if not released.rowcount:
            raise RuntimeError("成员写入锁已变化")
        record.group_membership_id = membership_id
        record.step, record.worker_config_hash = "group_entitlement_pending", frozen_config
        entitlement_context(db, record)
        sync_numbered_items(db, record)
        db.commit()


def _run_one(gateway_factory, account_id, record_id):
    job = claim(account_id=account_id, record_id=record_id)
    if not job:
        return False
    record_id, token = job
    step = "create_user"
    reconciling = False
    recovering_write = False
    recovering_membership = False
    membership_accepted = False
    frozen_config = None
    gateway = None
    try:
        with SessionLocal() as db:
            r = load(db, record_id, token)
            step = r.step
            # Saved write intent stays uncertain even if proxy/credential setup
            # fails before the gateway can query the previous remote result.
            reconciling = step == "subscribe_pending"
            recovering_membership = step == "group_membership_pending"
            recovering_write = step in PENDING_STEPS
            if r.active_operation_id:
                raise AwsFailure("记录已有其他操作，不能继续创建或自动重试", code="operation_in_progress")
            # Membership recovery changes step, but never the admitted job kind.
            batch = db.get(Batch, r.batch_id) if r.batch_id else None
            subscribe_existing = (
                batch is not None and batch.kind == "subscribe_existing"
            )
            account = db.get(AwsAccount, r.aws_account_id)
            frozen_config = attempt_config(db, account, r.worker_config_hash
                                           if recovering_write else retry_config(db, "sso", record_id))
            from .provisioning_coordinator import record_guard
            record_guard(db, r, recovering=recovering_write)
            user = db.get(User, r.owner_id)
            allowed = (
                user.active
                and not user.deleted_at
                and account.active
                and not account.deleted_at
                and (
                    r.provision_only
                    or (
                        db.get(Plan, r.plan_id).active
                        and not db.get(Plan, r.plan_id).deleted_at
                    )
                )
                and (user.role == "admin" or db.get(Binding, (user.id, account.id)))
            )
            # Keep remote provisioning outside the read transaction too; all
            # durable updates use the separate, lease-checked helper sessions.
            db.expunge_all()
            db.rollback()
            gateway = gateway_factory(account)

            def before_write():
                with SessionLocal() as guard_db:
                    current = load(guard_db, record_id, token)
                    if current.active_operation_id:
                        raise AwsFailure("记录已有其他操作，不能继续创建或订阅")
                    check_provisioning(guard_db, current,
                        guard_db.get(AwsAccount, current.aws_account_id), frozen_config)
                    if current.group_id:
                        from .group_subscription_state import checkpoint_join
                        checkpoint_join(guard_db, current.id, mark_intent=False,
                                        preparing_credentials=current.step in CREDENTIAL_STEPS)

            gateway.before_provisioning_write = before_write
            if step == "group_entitlement_pending":
                from .group_subscription_state import check_entitlement
                finish_sso(record_id, token, check_entitlement(record_id, gateway))
                return True
            if step == "password_pending":
                raise AwsFailure("一次性密码结果不明，原明文无法恢复；请使用“重置一次性密码”确认生成新密码后继续", uncertain=True)
            if step == "create_user_pending":
                lookup = getattr(gateway, "find_created_user", None)
                user_id = lookup(r) if lookup else None
                if not user_id:
                    raise AwsFailure("尚未确认原请求创建的 SSO 用户；仅只读核对，不能重复创建", uncertain=True)
                # Finish this read-only recovery pass. A later, freshly guarded
                # attempt may provision its password and remaining membership.
                save(record_id, token, sso_user_id=user_id,
                     sso_display_name=f"Kiro Console {r.id}", step="password",
                     worker_config_hash=None, state="queued", lease_token=None, lease_until=None)
                with SessionLocal() as retry_db:
                    settle_retry(retry_db, "sso", record_id)
                    retry_db.commit()
                return True
            # A previous subscription call may have succeeded even when local DB
            # commit failed. Always reconcile it, including after user disablement.
            if reconciling:
                if gateway.is_subscribed(r):
                    finish(record_id, token)
                else:
                    fail(
                        record_id,
                        token,
                        "尚未在 AWS 查到对应订阅；保留处理中次数，请稍后再次核对",
                        uncertain=True,
                        error=AwsFailure("订阅只读核对尚未确认", uncertain=True,
                                         code="subscription_assignment_propagating", retryable=True),
                        frozen_config=frozen_config,
                    )
                return True
            native_join = None
            if r.group_id:
                from .group_subscription_state import check_join
                native_join = check_join(r.id, r.group_id, gateway,
                    recovering=recovering_membership,
                    preparing_credentials=step in CREDENTIAL_STEPS)
                membership_accepted = bool(native_join and recovering_membership)
            if not allowed and not (recovering_membership and r.provision_only):
                raise AwsFailure("创建者、AWS 绑定或套餐已停用")
            if subscribe_existing and (not r.sso_user_id or r.sso_deleted_at):
                raise AwsFailure("原有 SSO 用户已失效，请同步状态后核对")
            if not r.provision_only:
                ensure_not_expired(db, r)
            if r.provision_only:
                gateway.verify_identity()
            else:
                gateway.verify()
            if not r.sso_user_id:
                def before_create():
                    nonlocal step
                    save(record_id, token, step="create_user_pending", frozen_config=frozen_config,
                         check_native_creation=bool(r.group_id))
                    step = "create_user_pending"

                gateway.before_create_user = before_create
                before_create()
                user_id = gateway.create_user(r)
                save(
                    record_id,
                    token,
                    sso_user_id=user_id,
                    sso_display_name=f"Kiro Console {r.id}",
                    step="password",
                    worker_config_hash=None,
                )
                r.sso_user_id = user_id
                step = "password"
            # A subscription assignment needs the SSO ID, not its login password.
            # Missing/unknown credentials may retain a still-valid recovery candidate.
            if (
                not subscribe_existing
                and not r.password_encrypted
                and r.credential_state == "one_time"
                and not r.credential_recovery_encrypted
            ):
                save(record_id, token, step="password_pending", credential_state="unknown",
                     frozen_config=frozen_config, check_native_creation=bool(native_join))
                step = "password_pending"
                password = gateway.password(r)
                save(
                    record_id,
                    token,
                    password_encrypted=encrypt(password),
                    password_generated_at=now(),
                    step="subscribe",
                    credential_state="one_time",
                    worker_config_hash=None,
                )
                r.password_encrypted = encrypt(password)
                step = "subscribe"
            if r.group_id:
                if native_join:
                    if not membership_lock(record_id, token, frozen_config):
                        save(record_id, token, state="queued", step="subscribe",
                             lease_token=None, lease_until=None)
                        return True
                    native_join = check_join(r.id, r.group_id, gateway, recovering=recovering_membership)
                with db.no_autoflush:
                    group = db.get(ManagedGroup, r.group_id)
                    if group:
                        db.expunge(group)
                    db.rollback()
                if not group or group.state != "ready" or not group.remote_id:
                    raise AwsFailure("AWS 分组尚未就绪")
                membership_id = gateway.get_group_membership(
                    group.remote_id, r.sso_user_id
                )
                if not membership_id:
                    if recovering_membership:
                        raise AwsFailure("AWS 成员加入尚未确认，不能重复发送", uncertain=True)
                    check_join(r.id, group.id, gateway)
                    save(record_id, token, step="group_membership_pending", frozen_config=frozen_config)
                    step = "group_membership_pending"
                    gateway.create_group_membership(group.remote_id, r.sso_user_id)
                    membership_accepted = bool(native_join)
                    membership_id = gateway.get_group_membership(
                        group.remote_id, r.sso_user_id
                    )
                    if not membership_id:
                        raise AwsFailure("AWS 分组成员尚未确认", uncertain=True)
                check_join(r.id, group.id, gateway, recovering=True)
                if native_join:
                    # Membership and its exact GROUP claim are proved above.
                    # Aggregate propagation retains the record intent/quota,
                    # while a sibling can now acquire the group write lock.
                    await_group_entitlement(record_id, token, membership_id, frozen_config)
                    step = "group_entitlement_pending"
                else:
                    step = "subscribe"
                    save(record_id, token, group_membership_id=membership_id, step=step)
                recovering_membership = False
            if r.provision_only:
                observation = None
                if native_join:
                    from .group_subscription_state import check_entitlement
                    observation = check_entitlement(record_id, gateway)
                finish_sso(record_id, token, observation)
                return True
            # Persist the intent BEFORE the non-idempotent external write.
            ensure_not_expired(db, r)
            save(record_id, token, step="subscribe_pending", frozen_config=frozen_config)
            step = "subscribe_pending"
            request_id = gateway.subscribe(r)
            finish(record_id, token, request_id)
    except AwsFailure as exc:
        fail(
            record_id,
            token,
            str(exc),
            uncertain=recovering_write
            or membership_accepted
            or recovering_membership
            or (
                step in PENDING_STEPS
                and exc.uncertain
            ),
            error=exc, frozen_config=frozen_config,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        fail(
            record_id,
            token,
            f"AWS 操作失败：{code}",
            uncertain=recovering_write or membership_accepted or recovering_membership
            or (step in PENDING_STEPS and not classify_failure(exc).proven_unsent),
            error=exc, frozen_config=frozen_config,
        )
    except Exception as exc:
        # Don't include raw exceptions, which may contain credentials/request data.
        logger.error("Job %s failed: %s", record_id, type(exc).__name__)
        try:
            fail(
                record_id,
                token,
                f"操作中断（{type(exc).__name__}），请继续处理",
                uncertain=recovering_write or membership_accepted or recovering_membership
                or (step in PENDING_STEPS and not classify_failure(exc).proven_unsent),
                error=exc, frozen_config=frozen_config,
            )
        except Exception:
            logger.error("Job %s remains leased for safe recovery", record_id)
    finally:
        close = getattr(gateway, "close", None)
        if close:
            try:
                close()
            except Exception as exc:
                logger.error("Job %s transport cleanup failed: %s", record_id, type(exc).__name__)
    return True


def make_dispatcher(*, gateway_factory=None, max_workers=None):
    from . import group_subscription_worker as native
    from . import provisioning_coordinator as coordinator

    def candidates():
        families = ["provisioning", "lifecycle", "group", "native", "schedule", "native_due"]
        if settings.plan_changes_enabled:
            families += ["plan", "plan_due"]
        return ([(aid, "control", "") for aid in candidate_accounts(*families)]
                + [(aid, "sso", rid) for aid, rid in candidate_records()])

    def run_task(task):
        aid, family, rid = task
        if family == "sso":
            return run_one(gateway_factory, account_id=aid, record_id=rid)
        with account_fence(aid) as acquired:
            return run_control(aid) if acquired else False

    def run_control(aid):
        # Each family gets bounded work before this account returns its slot.
        steps = (
            lambda: native.enqueue_due(limit=1, account_id=aid),
            lambda: enqueue_due(limit=1, account_id=aid),
            lambda: reconcile_due(gateway_factory, limit=1, account_id=aid),
            lambda: run_plan_change(gateway_factory, account_id=aid),
            lambda: run_operation(gateway_factory, account_id=aid),
            lambda: native.reconcile_due(gateway_factory, limit=1, account_id=aid),
            lambda: coordinator.run_one(account_id=aid),
            lambda: native.run_one(gateway_factory, account_id=aid),
            lambda: run_group_job(gateway_factory, account_id=aid),
        )
        worked = False
        for step in steps:
            if dispatcher.stopped.is_set():
                break
            worked = bool(step()) or worked
        return worked

    dispatcher = AccountDispatcher(candidates, run_task,
        max_workers=settings.worker_concurrency if max_workers is None else max_workers,
        account_key=lambda task: task[0], max_per_account=settings.per_account_concurrency,
        fence=lambda task: nullcontext(True))
    return dispatcher


def main():
    logging.basicConfig(level=logging.INFO)
    dispatcher = make_dispatcher()

    def stop(*_):
        dispatcher.stop()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not dispatcher.stopped.is_set():
            try:
                dispatcher.tick()
            except Exception as exc:
                logger.error("Queue error: %s", type(exc).__name__)
            dispatcher.stopped.wait(0.2)
    finally:
        # A hung wire call keeps its account locked until it returns or systemd
        # terminates the process at TimeoutStopSec; never cancel a running lane.
        dispatcher.close(wait=True)


if __name__ == "__main__":
    main()
