from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event, Lock
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import aws_reports


def test_reads_coalesces_concurrent_fresh_reads_and_force_refresh(monkeypatch):
    cache = aws_reports.CostReads()
    entered, release = Event(), Event()
    waiting, mutex, count = Event(), Lock(), []
    class WaitingFuture(Future):
        def result(self, *args, **kwargs):
            with mutex:
                count.append(1)
                if len(count) == 2:
                    waiting.set()
            return super().result(*args, **kwargs)
    monkeypatch.setattr(aws_reports, "Future", WaitingFuture)
    calls = []
    def load():
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return {"amount": "0.3"}
    with ThreadPoolExecutor(3) as executor:
        first = executor.submit(cache.get, "key", load, True)
        assert entered.wait(5)
        second = executor.submit(cache.get, "key", load, True)
        third = executor.submit(cache.get, "key", load)
        assert waiting.wait(5)
        release.set()
        assert first.result()["amount"] == second.result()["amount"] == third.result()["amount"] == "0.3"
    assert len(calls) == 1


def test_sequential_reads_are_fresh_and_only_manual_refresh_timestamps_are_retained(monkeypatch):
    clock = [0]
    monkeypatch.setattr(aws_reports, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    cache = aws_reports.CostReads(capacity=2)
    calls = []
    def load():
        calls.append(1)
        return {"amount": str(len(calls))}
    assert cache.get("a", load)["amount"] == "1"
    assert cache.get("a", load)["amount"] == "2"
    assert cache.get("a", load, True)["amount"] == "3"
    with pytest.raises(HTTPException) as exc:
        cache.get("a", load, True)
    assert exc.value.status_code == 429
    # Ordinary reads remain fresh even within the manual refresh cooldown.
    assert cache.get("a", load)["amount"] == "4"
    clock[0] += 31
    assert cache.get("a", load, True)["amount"] == "5"
    cache.get("b", load, True)
    cache.get("c", load, True)
    assert list(cache.refreshed) == ["b", "c"]
    assert all(isinstance(value, (int, float)) for value in cache.refreshed.values())
    assert not cache.pending


def test_reads_errors_are_not_cached_and_global_inflight_is_bounded():
    cache = aws_reports.CostReads(max_inflight=1)
    def failure():
        raise ValueError("unavailable")
    for _ in range(2):
        with pytest.raises(ValueError):
            cache.get("failed", failure)
    entered, release = Event(), Event()
    def pending():
        entered.set()
        assert release.wait(5)
        return {"ok": True}
    with ThreadPoolExecutor(1) as executor:
        job = executor.submit(cache.get, "a", pending)
        assert entered.wait(5)
        try:
            with pytest.raises(HTTPException) as exc:
                cache.get("b", lambda: {"unexpected": True})
            assert exc.value.status_code == 429
        finally:
            release.set()
        assert job.result() == {"ok": True}


@pytest.mark.parametrize("failure", [False, True])
def test_refresh_joining_regular_read_sets_cooldown_only_after_success(monkeypatch, failure):
    cache = aws_reports.CostReads()
    entered, release, joined = Event(), Event(), Event()
    calls = []
    class WaitingFuture(Future):
        def result(self, *args, **kwargs):
            joined.set()
            return super().result(*args, **kwargs)
    monkeypatch.setattr(aws_reports, "Future", WaitingFuture)
    def load():
        calls.append(1)
        entered.set()
        assert release.wait(5)
        if failure:
            raise ValueError("unavailable")
        return {"amount": "0.3"}
    with ThreadPoolExecutor(2) as executor:
        regular = executor.submit(cache.get, "key", load)
        assert entered.wait(5)
        refreshed = executor.submit(cache.get, "key", load, True)
        assert joined.wait(5)
        release.set()
        if failure:
            for pending in (regular, refreshed):
                with pytest.raises(ValueError, match="unavailable"):
                    pending.result()
        else:
            assert regular.result() == refreshed.result() == {"amount": "0.3"}
    assert len(calls) == 1
    if failure:
        assert cache.get("key", lambda: {"amount": "0.4"}, True) == {"amount": "0.4"}
    else:
        with pytest.raises(HTTPException) as exc:
            cache.get("key", load, True)
        assert exc.value.status_code == 429
        assert len(calls) == 1
