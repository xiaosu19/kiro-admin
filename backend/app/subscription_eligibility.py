"""Pure checks over locally confirmed subscription access; no remote I/O."""
from datetime import datetime, timezone
from .catalog import BY_SUBSCRIPTION_TYPE


SUBSCRIPTION_REQUIRED = "订阅尚未确认生效或访问已到期，请先完成订阅并核对状态后再导出 JSON"


def has_confirmed_subscription_access(record, instant):
    status = record.subscription_status
    if status not in ("active", "cancel_scheduled"):
        return False
    expires = record.access_ends_at
    if expires is None:
        # An ongoing active subscription has no scheduled end. A cancelled
        # renewal needs a confirmed future end before access can be assumed.
        return status == "active"
    if not isinstance(expires, datetime) or not isinstance(instant, datetime):
        return False
    expires = expires.replace(tzinfo=timezone.utc) if expires.tzinfo is None else expires
    instant = instant.replace(tzinfo=timezone.utc) if instant.tzinfo is None else instant
    return expires > instant


def has_observed_paid_entitlement(usage):
    """Token-backed paid-plan metadata, never proof of billing state or lifetime."""
    info = usage.get("subscriptionInfo") if isinstance(usage, dict) else None
    return (isinstance(info, dict) and isinstance(info.get("type"), str)
            and info["type"] in BY_SUBSCRIPTION_TYPE
            and info.get("status", "ACTIVE") == "ACTIVE")
