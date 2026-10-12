"""Independent users overlap while exact users and account control remain fenced."""
import concurrent.futures
import threading

from app.account_dispatcher import account_fence
from app.auth_jobs import run_one
from test_auth_batches import Gateway, admission, record
from app.enterprise_auth import EnterpriseAuth


def test_two_users_in_one_account_authenticate_concurrently_and_keep_control_fence(alice):
    records = [record(username='parallel-one'), record(username='parallel-two')]
    assert admission(alice, records).status_code == 202
    entered = [threading.Event(), threading.Event()]
    release = threading.Event()

    class Waiting(EnterpriseAuth):
        def begin(self, username, *args, **kwargs):
            entered[0 if username == records[0].username else 1].set()
            assert release.wait(5)
            return super().begin(username, *args, **kwargs)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run_one, Gateway, Waiting, account_id=1, record_id=r.id, maintenance=False) for r in records]
        try:
            assert all(event.wait(3) for event in entered)
            with account_fence(1) as acquired:
                assert not acquired, 'account-wide deletion cannot overlap either login'
            assert run_one(Gateway, Waiting, account_id=1, record_id=records[0].id, maintenance=False) is False
        finally:
            release.set()
        assert all(f.result(timeout=3) for f in futures)
    with account_fence(1) as acquired:
        assert acquired


def test_different_records_with_same_login_principal_never_overlap(alice):
    first, second = record(username='same-principal'), record(username='Same-Principal')
    assert admission(alice, [first, second]).status_code == 202
    entered, release = threading.Event(), threading.Event()
    visits = []

    class Waiting(EnterpriseAuth):
        def begin(self, *args, **kwargs):
            visits.append(1); entered.set()
            assert release.wait(5)
            return super().begin(*args, **kwargs)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(run_one, Gateway, Waiting, account_id=1, record_id=first.id, maintenance=False)
        try:
            assert entered.wait(3)
            assert pool.submit(run_one, Gateway, Waiting, account_id=1, record_id=second.id, maintenance=False).result(timeout=2) is False
            assert len(visits) == 1
        finally:
            release.set()
        assert future.result(timeout=3)
