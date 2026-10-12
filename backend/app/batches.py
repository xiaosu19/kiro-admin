"""Batch admission is atomic; each AWS job has independent durable results."""

import hashlib
import json
import re
import uuid
from typing import Literal

from fastapi import Depends, HTTPException, Request
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .database import get_db
from .email_addresses import generated_email
from .models import AwsAccount, Batch, BatchItem, Binding, Plan, Subscription, User, now
from .security import audit, get_user
from .schemas import StopPolicy
from .schedules import configure


class BatchRow(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{2,70}$")
    email: EmailStr | None = None

    @field_validator("email", mode="before")
    @classmethod
    def blank_email(cls, value):
        return value.strip() or None if isinstance(value, str) else value


class SequenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    pattern: str = Field(min_length=5, max_length=85)
    email_template: str = Field(default="", max_length=254)

    def rows(self):
        match = re.fullmatch(
            r"([a-zA-Z0-9_.-]{1,60})-(\d{1,7})-(\d{1,7})", self.pattern
        )
        if not match:
            raise ValueError("编号格式应为 member-01-10")
        prefix, first, last = match.groups()
        first, last = int(first), int(last)
        if first < 1 or last < first or last > 1000000 or last - first + 1 > 100:
            raise ValueError(
                "起始编号至少为 1，每批最多 100 个，结束编号不超过 1000000"
            )
        return [
            BatchRow(
                username=f"{prefix}-{n}",
                email=self.email_template.replace("{n}", str(n)) or None,
            )
            for n in range(first, last + 1)
        ]

    @model_validator(mode="after")
    def validate_sequence(self):
        self.rows()
        return self


class CreateBatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["sso", "subscribed"]
    aws_account_id: int
    group_id: str | None = None
    plan_id: int | None = None
    items: list[BatchRow] | None = Field(default=None, min_length=1, max_length=100)
    sequence: SequenceInput | None = None
    request_key: str = Field(min_length=16, max_length=80)
    export_credentials: bool = False
    stop_schedule: StopPolicy | None = None

    @model_validator(mode="after")
    def valid_plan(self):
        if (self.items is None) == (self.sequence is None):
            raise ValueError("请选择用户列表或编号生成中的一种方式")
        if (self.kind == "sso") != (self.plan_id is None):
            raise ValueError("仅创建 SSO 不指定套餐，创建并订阅必须指定套餐")
        if (
            self.kind == "sso"
            and self.stop_schedule
            and self.stop_schedule.mode != "none"
        ):
            raise ValueError("仅创建 SSO 无需设置停止订阅时间，请在开通订阅时设置")
        emails = [str(r.email).lower() for r in self.rows() if r.email]
        if len(emails) != len(set(emails)):
            raise ValueError(
                "AWS 要求每名用户的邮箱唯一；请使用含 {n} 的邮箱模板或留空自动生成"
            )
        return self

    def rows(self):
        return self.sequence.rows() if self.sequence else self.items


class SubscribeBatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_ids: list[str] = Field(min_length=1, max_length=100)
    plan_id: int
    group_id: str | None = None
    request_key: str = Field(min_length=16, max_length=80)
    stop_schedule: StopPolicy | None = None

    @model_validator(mode="after")
    def unique_records(self):
        if len(set(self.record_ids)) != len(self.record_ids):
            raise ValueError("不能重复选择同一 SSO 用户")
        return self


def batch_view(db, batch, details=False):
    items = list(
        db.scalars(
            select(BatchItem)
            .where(BatchItem.batch_id == batch.id)
            .order_by(BatchItem.id)
        )
    )
    result = {
        "id": batch.id,
        "owner_id": batch.owner_id,
        "export_credentials": batch.export_credentials,
        "kind": batch.kind,
        "group_id": batch.group_id,
        "created_at": batch.created_at,
        "total": len(items),
        "states": {
            state: sum(i.state == state for i in items)
            for state in ("queued", "running", "completed", "failed", "needs_review")
        },
    }
    if details:
        result["items"] = [
            {
                "id": i.record_id,
                "state": i.state,
                "error": i.error,
                "username": db.get(Subscription, i.record_id).username,
                "email": db.get(Subscription, i.record_id).email,
                "has_credentials": bool(
                    (r := db.get(Subscription, i.record_id)).sso_user_id
                    and r.password_encrypted
                    and not r.sso_deleted_at
                    and not r.active_operation_id
                ),
            }
            for i in items
        ]
    return result


def batch_intent(db, actor, body, kind):
    exclude = {"request_key"}
    if not getattr(body, "group_id", None):
        exclude.add("group_id")
    if not body.stop_schedule or (
        body.stop_schedule.mode == "none" and not getattr(body, "group_id", None)
    ):
        exclude.add("stop_schedule")
    if not getattr(body, "export_credentials", False):
        # Preserve hashes for batches admitted before the export option existed.
        exclude.add("export_credentials")
    digest = hashlib.sha256(
        json.dumps(
            body.model_dump(mode="json", exclude=exclude), sort_keys=True
        ).encode()
    ).hexdigest()
    old = db.scalar(
        select(Batch).where(
            Batch.owner_id == actor.id, Batch.request_key == body.request_key
        )
    )
    if old:
        if old.payload_hash != digest or old.kind != kind:
            raise HTTPException(409, "重复请求标识与原批次内容不同")
        return old, True
    batch = Batch(
        id=str(uuid.uuid4()),
        owner_id=actor.id,
        request_key=body.request_key,
        payload_hash=digest,
        kind=kind,
        group_id=getattr(body, "group_id", None),
        export_credentials=getattr(body, "export_credentials", False),
    )
    db.add(batch)
    db.flush()
    return batch, False


def require_account(db, actor, account):
    if (
        not account
        or account.deleted_at
        or not account.active
        or (actor.role != "admin" and not db.get(Binding, (actor.id, account.id)))
    ):
        raise HTTPException(403, "无权使用该 AWS 账号")


def require_plan(db, plan_id):
    plan = db.get(Plan, plan_id)
    if not plan or plan.deleted_at or not plan.active:
        raise HTTPException(404, "套餐不存在或已停用")
    return plan


def update_batch_item(db, record, state, error=None):
    if record.batch_id:
        db.execute(
            update(BatchItem)
            .where(
                BatchItem.batch_id == record.batch_id, BatchItem.record_id == record.id
            )
            .values(state=state, error=error)
        )


def register_batch_routes(app, reserve):
    @app.post("/api/batches/create", status_code=202)
    def create_batch(
        body: CreateBatchInput,
        request: Request,
        actor: User = Depends(get_user),
        db: Session = Depends(get_db),
    ):
        batch, existed = batch_intent(db, actor, body, body.kind)
        if existed:
            return batch_view(db, batch, True)
        account = db.get(AwsAccount, body.aws_account_id)
        require_account(db, actor, account)
        from .groups import require_group

        group = (
            require_group(db, body.group_id, actor, account.id)
            if body.group_id
            else None
        )
        owner = db.get(User, group.owner_id) if group else actor
        if not owner.active or owner.deleted_at:
            raise HTTPException(409, "分组所有者已停用")
        require_account(db, owner, account)
        from .group_subscription_state import live_grant, reserve_join
        native = live_grant(db, group.id) if group else None
        if native and body.kind == "subscribed":
            raise HTTPException(409, "原生订阅分组会自动授权，请选择仅创建 SSO，按分组套餐扣次")
        plan = require_plan(db, body.plan_id) if body.kind == "subscribed" else None
        items = body.rows()
        if body.sequence and db.scalar(
            select(Subscription.id)
            .where(
                Subscription.aws_account_id == account.id,
                Subscription.username.in_([item.username for item in items]),
            )
            .limit(1)
        ):
            raise HTTPException(409, "编号范围包含已使用的用户名，请调整起始编号后重试")
        for index, item in enumerate(items):
            counter_id, cycle = reserve(db, owner, plan.id) if plan else (None, None)
            rid = str(uuid.uuid4())
            username = item.username if body.sequence else f"{item.username}-{rid[:8]}"
            record = Subscription(
                id=rid,
                owner_id=owner.id,
                aws_account_id=account.id,
                plan_id=plan.id if plan else None,
                subscription_type=plan.subscription_type if plan else None,
                plan_name_snapshot=plan.name if plan else None,
                provision_only=plan is None,
                batch_id=batch.id,
                group_id=group.id if group else None,
                counter_id=counter_id,
                cycle_number=cycle,
                reserved=counter_id is not None,
                request_key=f"batch:{batch.id}:{index}",
                username=username,
                email=str(item.email) if item.email else generated_email(username),
                portal_url=account.portal_url,
            )
            db.add(record)
            db.flush()
            if native:
                reserve_join(db, group, record, actor, record.id)
            if body.stop_schedule:
                configure(
                    db, record, actor, body.stop_schedule, request, preserve_none=True
                )
            elif record.group_id:
                from .group_policies import inherit

                inherit(db, record, actor, request)
            if plan:
                from .group_policies import ensure_paid_deadline

                ensure_paid_deadline(db, record)
            db.add(BatchItem(batch_id=batch.id, record_id=rid))
        db.flush()
        audit(
            db,
            actor,
            "create_batch",
            f"批量{'创建 SSO 并订阅 ' + plan.name if plan else '创建 SSO'}：{len(items)} 个",
            subject=actor.id,
            request=request,
        )
        db.commit()
        return batch_view(db, batch, True)

    @app.post("/api/batches/subscribe", status_code=202)
    def subscribe_batch(
        body: SubscribeBatchInput,
        request: Request,
        actor: User = Depends(get_user),
        db: Session = Depends(get_db),
    ):
        batch, existed = batch_intent(db, actor, body, "subscribe_existing")
        if existed:
            return batch_view(db, batch, True)
        plan = require_plan(db, body.plan_id)
        from .groups import owned_group, subscription_skip_reason

        group = owned_group(db, body.group_id, actor) if body.group_id else None
        if group and (group.state != "ready" or group.active_job_id):
            raise HTTPException(409, "分组尚未就绪")
        for record_id in body.record_ids:
            r = db.get(Subscription, record_id)
            if not r or (actor.role != "admin" and r.owner_id != actor.id):
                raise HTTPException(404, "选择的 SSO 用户不存在")
            if group and (
                r.group_id != group.id
                or r.owner_id != group.owner_id
                or r.aws_account_id != group.aws_account_id
            ):
                raise HTTPException(409, "选择的 SSO 用户已不属于该分组")
            if r.group_id:
                from .group_subscription_state import live_grant
                if live_grant(db, r.group_id):
                    raise HTTPException(409, "原生订阅分组不能再单独开通 USER 套餐")
                member_group = owned_group(db, r.group_id, actor)
                if member_group.state != "ready" or member_group.active_job_id:
                    raise HTTPException(409, "分组尚未就绪")
            require_account(db, actor, db.get(AwsAccount, r.aws_account_id))
            owner = db.get(User, r.owner_id)
            require_account(db, owner, db.get(AwsAccount, r.aws_account_id))
            if not owner.active:
                raise HTTPException(409, "SSO 创建者已停用")
            if subscription_skip_reason(r):
                raise HTTPException(
                    409,
                    "仅可选择已完成创建、尚未绑定套餐、未发现现有订阅且未删除的 SSO 用户",
                )
            changed = db.execute(
                update(Subscription)
                .where(
                    Subscription.id == r.id,
                    Subscription.plan_id.is_(None),
                    Subscription.state == "completed",
                    Subscription.active_operation_id.is_(None),
                    Subscription.sso_deleted_at.is_(None),
                )
                .values(
                    plan_id=plan.id,
                    plan_name_snapshot=plan.name,
                    subscription_type=plan.subscription_type,
                    provision_only=False,
                    state="queued",
                    step="subscribe",
                    batch_id=batch.id,
                    error=None,
                    updated_at=now(),
                )
            )
            if not changed.rowcount:
                raise HTTPException(409, "SSO 用户刚发生变化，请刷新后重新选择")
            counter_id, cycle = reserve(db, owner, plan.id)
            r.counter_id, r.cycle_number, r.reserved = (
                counter_id,
                cycle,
                counter_id is not None,
            )
            db.add(BatchItem(batch_id=batch.id, record_id=r.id))
            if body.stop_schedule:
                configure(db, r, actor, body.stop_schedule, request, preserve_none=True)
            elif r.group_id:
                from .group_policies import inherit

                inherit(db, r, actor, request)
            from .group_policies import ensure_paid_deadline

            ensure_paid_deadline(db, r)
            audit(
                db,
                actor,
                "batch_subscribe",
                f"批量开通 {plan.name}：{r.username}",
                subject=r.owner_id,
                request=request,
            )
        db.commit()
        return batch_view(db, batch, True)

    @app.get("/api/batches")
    def list_batches(actor: User = Depends(get_user), db: Session = Depends(get_db)):
        q = select(Batch)
        if actor.role != "admin":
            q = q.where(Batch.owner_id == actor.id)
        return [
            batch_view(db, b)
            for b in db.scalars(q.order_by(Batch.created_at.desc()).limit(30))
        ]

    @app.get("/api/batches/{batch_id}")
    def get_batch(
        batch_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
    ):
        b = db.get(Batch, batch_id)
        if not b or (actor.role != "admin" and b.owner_id != actor.id):
            raise HTTPException(404, "批次不存在")
        return batch_view(db, b, True)


def admit_frozen_sso(db, actor, account_batch, item):
    """Trusted numbered intent only; public schemas never accept identity overrides.

    Caller owns the transaction, including the quota reservation and child link.
    The immutable record UUID is also the recovery key if a caller lost its link.
    """
    from .groups import require_group
    from .group_subscription_state import reserve_join
    from .group_policies import inherit

    old = db.get(Subscription, item.record_id)
    if old:
        if (old.owner_id, old.aws_account_id, old.username, old.email, old.group_id) != (
            actor.id, account_batch.aws_account_id, item.username, item.email, account_batch.group_id
        ):
            raise HTTPException(409, "已受理 SSO 的冻结身份已变化，请核对")
        return old
    account = db.get(AwsAccount, account_batch.aws_account_id)
    require_account(db, actor, account)
    group = require_group(db, account_batch.group_id, actor, account.id, actor.id)
    batch = Batch(id=str(uuid.uuid4()), owner_id=actor.id, request_key=f"numbered:{item.record_id}",
                  payload_hash=hashlib.sha256(item.record_id.encode()).hexdigest(), kind="sso",
                  group_id=group.id)
    db.add(batch)
    db.flush()
    record = Subscription(id=item.record_id, owner_id=actor.id, aws_account_id=account.id,
        provision_only=True, batch_id=batch.id, group_id=group.id, reserved=False,
        request_key=f"numbered:{item.record_id}", username=item.username, email=item.email,
        portal_url=account.portal_url)
    db.add(record)
    db.flush()
    reserve_join(db, group, record, actor, record.id)
    inherit(db, record, actor)
    db.add(BatchItem(batch_id=batch.id, record_id=record.id))
    audit(db, actor, "create_batch", f"编号批次创建 SSO：{item.internal_id}", subject=actor.id)
    return record
