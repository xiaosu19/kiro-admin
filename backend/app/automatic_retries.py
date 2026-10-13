"""Bounded, nonblocking durable backoff for existing fenced job runners."""

import json
from datetime import timedelta

from sqlalchemy import select

from .models import (
    GroupJob, NativeGroupOperation, ProvisioningAccountBatch, ProvisioningItem,
    Subscription, now,
)
from .retry_models import AutomaticRetry
from .retry_policy import MAX_AUTOMATIC_RETRIES, RETRY_DELAYS, classify_failure

PROPAGATION_CODES = frozenset(("subscription_observation_propagating", "subscription_assignment_propagating"))
PROPAGATION_WINDOW = timedelta(hours=24)
PROPAGATION_DELAYS = (60, 120, 300, 600, 900)


def ready_clause(family, job_column):
    return ~select(AutomaticRetry.job_id).where(
        AutomaticRetry.family == family, AutomaticRetry.job_id == job_column,
        AutomaticRetry.next_retry_at > now(),
    ).exists()


def retry_config(db, family, job_id):
    row = db.get(AutomaticRetry, (family, job_id))
    return row.config_hash if row and row.next_retry_at is not None else None


def settle_retry(db, family, job_id):
    row = db.get(AutomaticRetry, (family, job_id))
    if row:
        row.next_retry_at = None
        row.updated_at = now()


def provisioning_stopped(db, family, job):
    if family == "sso":
        item = db.get(ProvisioningItem, job.id)
        account_id = item.account_batch_id if item else None
    else:
        account_id = json.loads(job.payload).get("provisioning_account_id")
    row = db.get(ProvisioningAccountBatch, account_id) if account_id else None
    return bool(row and row.stop_requested_at)


def propagation_reconciliation_allowed(db, family, job_id, mode, code):
    """Aggregate propagation may resume only an existing read-only step."""
    if mode != "reconcile":
        return False
    if family == "sso":
        job = db.get(Subscription, job_id)
        steps = ("subscribe_pending",) if code == "subscription_assignment_propagating" else (
            "group_membership_pending", "group_entitlement_pending",
        )
        return bool(job and job.step in steps)
    if code != "subscription_observation_propagating":
        return False
    model = {"native": NativeGroupOperation, "group": GroupJob}.get(family)
    job = db.get(model, job_id) if model else None
    return bool(job and job.phase == "pending")


def schedule_retry(db, family, job_id, error, *, mode="retry", config_hash=None, stopped=False):
    failure = classify_failure(error)
    row = db.get(AutomaticRetry, (family, job_id))
    # A pending write permits reads, not assumptions about an unclassified
    # parser, validation or drift failure. Each retry needs an explicit cause.
    allowed = failure.transient
    if (failure.code in PROPAGATION_CODES
            and not propagation_reconciliation_allowed(db, family, job_id, mode, failure.code)):
        allowed = False
    if stopped or failure.stop or not allowed:
        settle_retry(db, family, job_id)
        return False
    if row is None:
        row = AutomaticRetry(family=family, job_id=job_id, retry_count=0)
        db.add(row)
    row.error_code, row.mode, row.updated_at = failure.code, mode, now()
    if failure.code in PROPAGATION_CODES:
        # A confirmed remote intent awaiting an eventually consistent read is
        # not a failed network attempt. Preserve its first observation deadline
        # across restarts and explicit rechecks; never resend the original write.
        row.propagation_started_at = row.propagation_started_at or now()
        row.propagation_last_checked_at = now()
        count = row.propagation_check_count or 0
        row.propagation_check_count = count + 1
        deadline = row.propagation_started_at + PROPAGATION_WINDOW
        if now() >= deadline:
            row.exhausted, row.next_retry_at = True, None
            return False
        row.config_hash = row.config_hash or config_hash
        delay = PROPAGATION_DELAYS[min(count, len(PROPAGATION_DELAYS) - 1)]
        row.next_retry_at = min(deadline, now() + timedelta(seconds=delay))
        row.exhausted = False
        return True
    if row.retry_count >= MAX_AUTOMATIC_RETRIES:
        row.exhausted, row.next_retry_at = True, None
        return False
    row.config_hash = row.config_hash or config_hash
    row.next_retry_at = now() + timedelta(seconds=RETRY_DELAYS[row.retry_count])
    row.retry_count += 1
    row.exhausted = False
    return True


def retry_view(db, family, job_id, *, active=True, rows=None, state=None):
    row = db.get(AutomaticRetry, (family, job_id)) if rows is None else rows.get((family, job_id))
    propagation = bool(row and row.propagation_started_at and row.error_code in PROPAGATION_CODES)
    deadline = row.propagation_started_at + PROPAGATION_WINDOW if propagation else None
    waiting = bool(propagation and active and row.next_retry_at is not None)
    timed_out = bool(state not in ("completed", "cancelled", "downloaded", "expired", "stopped") and propagation and row.exhausted and row.next_retry_at is None and now() >= deadline)
    return {
        "automatic_retry_count": row.retry_count if row else 0,
        "automatic_retry_limit": MAX_AUTOMATIC_RETRIES,
        "next_retry_at": row.next_retry_at if row and active else None,
        "retry_mode": row.mode if row and active and row.next_retry_at else None,
        "retry_exhausted": row.exhausted if row else False,
        "propagation_state": "waiting" if waiting else "timed_out" if timed_out else None,
        "propagation_started_at": row.propagation_started_at if propagation else None,
        "propagation_last_checked_at": row.propagation_last_checked_at if propagation else None,
        "propagation_deadline": deadline,
        "propagation_check_count": row.propagation_check_count if propagation else 0,
    }
