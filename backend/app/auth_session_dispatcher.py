"""Keep authentication capacity until the whole native/OIDC session yields.

A thread executes one guarded step. Its session still occupies capacity between
steps, during future polls and retry backoff. Durable metadata restores those
reservations after restart without loading credentials or encrypted workflows.
"""

from collections import Counter, deque
from dataclasses import dataclass

from .account_dispatcher import AccountDispatcher


@dataclass(frozen=True)
class AuthSession:
    task: tuple
    started: bool
    ready: bool
    running: bool = False


class AuthSessionDispatcher(AccountDispatcher):
    def __init__(self, session_candidates, run_account, **kwargs):
        self.session_candidates = session_candidates
        self._sessions, self._pending_sessions = set(), deque()
        super().__init__(self._session_tasks, run_account, **kwargs)

    def _session_tasks(self):
        candidates = {row.task: row for row in self.session_candidates()}
        # A finished DB row may still have transport cleanup running. Retain its
        # slot until AccountDispatcher has reaped the actual step future.
        self._sessions = {
            task for task in self._sessions
            if task in self._futures or task in candidates and candidates[task].started
        } | self._futures.keys()
        live = {task for task, row in candidates.items() if row.running and not row.ready}
        reserved = self._sessions | live
        self._pending_sessions = deque(
            task for task in self._pending_sessions
            if task in candidates and task not in self._sessions
        )
        waiting = set(self._pending_sessions)
        self._pending_sessions.extend(task for task in candidates if task not in waiting | self._sessions)

        active_accounts = Counter(self.account_key(task) for task in reserved)
        # A previous worker/version may have started more flows than today's
        # limit. Drain them in bounded groups; never start more while they wait.
        occupied = reserved | {task for task, row in candidates.items() if row.started}
        occupied_accounts = Counter(self.account_key(task) for task in occupied)
        for started in (True, False):
            remaining = len(self._pending_sessions)
            while self._pending_sessions and remaining and len(reserved) < self.max_workers:
                task = self._pending_sessions.popleft()
                remaining -= 1
                row, account = candidates[task], self.account_key(task)
                if row.started != started or task in live or not (row.started or row.ready):
                    self._pending_sessions.append(task)
                    continue
                if active_accounts[account] >= self.max_per_account:
                    self._pending_sessions.append(task)
                    continue
                if not started and (len(occupied) >= self.max_workers
                                    or occupied_accounts[account] >= self.max_per_account):
                    self._pending_sessions.append(task)
                    continue
                self._sessions.add(task)
                reserved.add(task)
                active_accounts[account] += 1
                if task not in occupied:
                    occupied.add(task)
                    occupied_accounts[account] += 1
                # Apply the same account rotation at session admission, instead
                # of rotating all queued logins after each network step.
                self._pending_sessions = deque(
                    [t for t in self._pending_sessions if self.account_key(t) != account]
                    + [t for t in self._pending_sessions if self.account_key(t) == account]
                )
        return [task for task in self._sessions if task in candidates and candidates[task].ready]
