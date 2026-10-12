"""Configuration checks for frozen worker attempts and pending-write recovery."""

from .aws import AwsFailure
from .group_subscription_state import config_hash
from .models import Binding, Plan, User
from .proxies import ProxyUnavailable, proxy_selection


def attempt_config(db, account, saved=None):
    if not account:
        raise AwsFailure("AWS 配置已不存在，请核对原操作")
    current = config_hash(db, account)
    if saved and current != saved:
        raise AwsFailure("AWS 账号或代理配置已变化，请恢复原配置后核对")
    return current


def check_config(db, account, frozen):
    attempt_config(db, account, frozen)
    try:
        proxy_selection(db, account.proxy_id)
    except ProxyUnavailable as exc:
        raise AwsFailure(str(exc)) from None


def check_provisioning(db, record, account, frozen, *, allow_stopped=False):
    """Recheck original creation authority before a fresh provisioning write."""
    from .provisioning_coordinator import record_guard
    record_guard(db, record, allow_stopped=allow_stopped)
    from .schedules import ensure_not_expired

    user = db.get(User, record.owner_id)
    plan = db.get(Plan, record.plan_id) if record.plan_id else None
    if (not user or not user.active or user.deleted_at
            or not account or not account.active or account.deleted_at
            or (user.role != "admin" and not db.get(Binding, (user.id, account.id)))
            or (not record.provision_only and (not plan or not plan.active or plan.deleted_at
                or plan.subscription_type != record.subscription_type))):
        raise AwsFailure("创建者、AWS 绑定或套餐已停用或变更")
    check_config(db, account, frozen)
    if not record.provision_only:
        ensure_not_expired(db, record)
