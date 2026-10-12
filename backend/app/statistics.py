"""Lifecycle totals are derived from retained records, never mutable quotas."""

from sqlalchemy import func, or_, select

from .models import Subscription


def cancelled_record():
    return or_(
        Subscription.cancelled_at.is_not(None),
        Subscription.subscription_status.in_(("cancelled", "cancel_scheduled")),
    )


def lifecycle_totals(db, owner_id=None):
    query = select(
        func.count().filter(cancelled_record()),
        func.count().filter(Subscription.sso_deleted_at.is_not(None)),
    ).select_from(Subscription)
    if owner_id is not None:
        query = query.where(Subscription.owner_id == owner_id)
    cancelled, deleted = db.execute(query).one()
    return {"cancelled_subscriptions": cancelled, "deleted_sso": deleted}
