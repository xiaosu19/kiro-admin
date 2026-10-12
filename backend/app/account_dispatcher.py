"""Bounded account lanes and the process fence shared by both worker services.

The database lease records recovery intent. The OS fence additionally prevents a
live, slow worker from overlapping a successor after that lease expires. Keep it
until result persistence and transport cleanup have finished, and never unlink a
lock file: another process may still have the same inode open.
"""

import fcntl
import hashlib
import logging
import os
import threading
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import and_, or_, select, union

from .config import settings
from .database import SessionLocal, engine
from .models import (
    AuthJob,
    GroupJob,
    ManagedGroup,
    NativeGroupGrant,
    NativeGroupOperation,
    PlanChange,
    ProvisioningAccountBatch,
    RecordOperation,
    StopSchedule,
    Subscription,
    now,
)

logger = logging.getLogger("kiro.dispatcher")
_held = threading.local()


@contextmanager
def _file_fence(path, *, shared=False):
    path = path.resolve()
    key = (os.getpid(), str(path))
    held = getattr(_held, "locks", None)
    if held is None:
        held = _held.locks = {}
    if key in held:
        # Never upgrade a shared holder to exclusive without competing against
        # other threads/processes. Exclusive holders can nest either mode.
        yield shared or not held[key][1]
        return
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        held[key] = (fd, shared)
        try:
            yield True
        finally:
            del held[key]
    finally:
        os.close(fd)


def account_fence(account_id, *, shared=False):
    """Independent record work shares the existing account-wide control fence."""
    base = settings.auth_worker_lock_path or Path(str(engine.url.database))
    return _file_fence(Path(str(base) + f".account-{int(account_id)}.lock"), shared=shared)


def resource_fence(namespace, resource_id):
    """Serialize the exact durable resource until wire cleanup and commit end."""
    base = settings.auth_worker_lock_path or Path(str(engine.url.database))
    digest = hashlib.sha256(f"{namespace}:{resource_id}".encode()).hexdigest()
    return _file_fence(Path(str(base) + f".resource-{digest}.lock"))


def record_scope(account_id):
    return (
        True
        if account_id is None
        else RecordOperation.record_id.in_(
            select(Subscription.id).where(Subscription.aws_account_id == account_id)
        )
    )


def group_scope(column, account_id):
    return (
        True
        if account_id is None
        else column.in_(
            select(ManagedGroup.id).where(ManagedGroup.aws_account_id == account_id)
        )
    )


def candidate_accounts(*families):
    """Read account IDs only, including disabled accounts with recoverable work."""
    queries = []
    for family in families:
        if family == "provisioning":
            query = select(ProvisioningAccountBatch.aws_account_id).where(
                ProvisioningAccountBatch.state.in_(("queued", "running", "stopping")))
        elif family == "sso":
            query = select(Subscription.aws_account_id).where(
                Subscription.state.in_(("queued", "running"))
            )
        elif family in ("lifecycle", "plan", "auth"):
            query = select(Subscription.aws_account_id).join(
                RecordOperation, RecordOperation.record_id == Subscription.id
            )
            if family == "auth":
                query = query.join(AuthJob, AuthJob.id == RecordOperation.id).where(
                    or_(
                        RecordOperation.state.in_(("queued", "running")),
                        and_(
                            RecordOperation.state == "polling",
                            AuthJob.next_poll_at <= now(),
                        ),
                    )
                )
            else:
                from .lifecycle import ACTION_NAMES
                from .plan_change_state import KINDS

                query = query.where(
                    RecordOperation.state.in_(("queued", "running")),
                    RecordOperation.kind.in_(
                        KINDS if family == "plan" else ACTION_NAMES
                    ),
                )
                if family == "lifecycle":
                    from .cascade_models import CascadeTask
                    queries.append(select(CascadeTask.aws_account_id).where(
                        CascadeTask.state.in_(("queued", "running"))))
        elif family in ("group", "native"):
            model = GroupJob if family == "group" else NativeGroupOperation
            query = (
                select(ManagedGroup.aws_account_id)
                .join(model, model.group_id == ManagedGroup.id)
                .where(model.state.in_(("queued", "running")))
            )
        elif family == "schedule":
            query = (
                select(Subscription.aws_account_id)
                .join(StopSchedule, StopSchedule.record_id == Subscription.id)
                .where(
                    StopSchedule.state.in_(("scheduled", "blocked")),
                    StopSchedule.stop_at <= now(),
                    or_(
                        StopSchedule.next_check_at.is_(None),
                        StopSchedule.next_check_at <= now(),
                    ),
                )
            )
        elif family == "plan_due":
            query = (
                select(Subscription.aws_account_id)
                .join(PlanChange, PlanChange.record_id == Subscription.id)
                .where(
                    PlanChange.scheduled_record_id.is_not(None),
                    Subscription.active_operation_id.is_(None),
                    or_(
                        PlanChange.next_check_at.is_(None),
                        PlanChange.next_check_at <= now(),
                    ),
                )
            )
        elif family == "native_due":
            query = (
                select(ManagedGroup.aws_account_id)
                .join(NativeGroupGrant, NativeGroupGrant.group_id == ManagedGroup.id)
                .where(
                    NativeGroupGrant.state.in_(("active", "cancel_scheduled")),
                    or_(
                        NativeGroupGrant.stop_at <= now(),
                        and_(
                            NativeGroupGrant.state == "cancel_scheduled",
                            NativeGroupGrant.access_ends_at <= now(),
                        ),
                    ),
                )
            )
        else:
            raise ValueError("Unknown worker family")
        queries.append(query)
    if not queries:
        return []
    with SessionLocal() as db:
        return sorted(set(db.scalars(union(*queries))))


def run_fenced(account_id, families, run):
    """Legacy callers discover first, close the session, then lock before claim."""
    accounts = [account_id] if account_id is not None else candidate_accounts(*families)
    for aid in accounts:
        with account_fence(aid) as acquired:
            if acquired:
                result = run(aid)
                if result:
                    return result
    return False


class AccountDispatcher:
    """Bounded tasks and per-account slots, rotating accounts at each free slot.

    tick() never waits for a running lane. stop() forbids admission and asks lanes
    to stop between steps; close() joins actual work without releasing its fence.
    Only the service's main thread calls tick/close; stop is signal-handler safe.
    """

    def __init__(
        self, candidate_accounts, run_account, *, max_workers=4, maintenance=None,
        account_key=None, max_per_account=1, fence=None,
    ):
        if max_workers < 1 or max_per_account < 1:
            raise ValueError("Worker limits must be positive")
        self.candidate_accounts, self.run_account = candidate_accounts, run_account
        self.max_workers, self.maintenance = max_workers, maintenance
        self.account_key = account_key or (lambda task: task)
        self.max_per_account = max_per_account
        self.fence = fence or account_fence
        self.stopped = threading.Event()
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="account"
        )
        self._futures, self._waiting = {}, deque()

    def _run(self, account_id):
        if self.stopped.is_set():
            return False
        with self.fence(account_id) as acquired:
            if not acquired or self.stopped.is_set():
                return False
            return self.run_account(account_id)

    def tick(self):
        for aid, future in list(self._futures.items()):
            if future.done():
                del self._futures[aid]
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Account %s step failed: %s", aid, type(exc).__name__)
        if self.stopped.is_set():
            return 0
        if self.maintenance:
            self.maintenance()
        candidates = set(self.candidate_accounts())
        self._waiting = deque(
            aid
            for aid in self._waiting
            if aid in candidates and aid not in self._futures
        )
        waiting = set(self._waiting)
        self._waiting.extend(sorted(candidates - waiting - self._futures.keys()))
        submitted = 0
        active_accounts = Counter(self.account_key(task) for task in self._futures)
        remaining = len(self._waiting)
        while (
            self._waiting
            and remaining
            and len(self._futures) < self.max_workers
            and not self.stopped.is_set()
        ):
            aid = self._waiting.popleft()
            remaining -= 1
            account = self.account_key(aid)
            if active_accounts[account] >= self.max_per_account:
                self._waiting.append(aid)
                continue
            self._futures[aid] = self._pool.submit(self._run, aid)
            active_accounts[account] += 1
            submitted += 1
            # Rotate whole accounts, so a large same-account batch cannot hide
            # smaller queues on other accounts behind thousands of record keys.
            self._waiting = deque(
                [task for task in self._waiting if self.account_key(task) != account]
                + [task for task in self._waiting if self.account_key(task) == account]
            )
        return submitted

    def stop(self):
        self.stopped.set()

    def close(self, wait=True):
        self.stop()
        self._pool.shutdown(wait=wait)
