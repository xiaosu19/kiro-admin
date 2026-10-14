"""One optional Chromium runtime with isolated, bounded per-challenge contexts.

Only the browser/driver process is shared. Pages, routes, cookies and HTTP/OCR
clients stay owned by their original challenge. Idle runtimes release resources.
"""
import atexit
import asyncio
import concurrent.futures
import threading
import time
from dataclasses import dataclass

IDLE_SECONDS = 15
MAX_USES = 100


@dataclass
class BrowserLease:
    resources: tuple
    dispose: object
    active: int = 0
    uses: int = 0
    dirty: bool = False


class BrowserRuntime:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.condition = None
        self.current = None
        self.idle_timer = None
        self.thread = threading.Thread(target=self.loop.run_forever,
                                       name='captcha-browser', daemon=True)
        self.thread.start()

    async def acquire(self, launch, dispose, deadline):
        if self.condition is None:
            self.condition = asyncio.Condition()
        async with self.condition:
            if self.idle_timer:
                self.idle_timer.cancel()
                self.idle_timer = None
            while (lease := self.current):
                if not lease.resources[1].is_connected():
                    lease.dirty = True
                if not lease.dirty:
                    break
                if lease.active:
                    # The caller's timeout also bounds this wait. Never kill
                    # another account's live context to rotate the process.
                    await self.condition.wait()
                    continue
                await self._dispose(lease)
                lease = None
            if lease is None:
                lease = BrowserLease(await launch(deadline), dispose)
                self.current = lease
            lease.active += 1
            lease.uses += 1
            return lease

    async def release(self, lease, *, dirty=False):
        async with self.condition:
            lease.active -= 1
            lease.dirty = lease.dirty or dirty or lease.uses >= MAX_USES
            if lease.active == 0:
                if lease.dirty:
                    await self._dispose(lease)
                else:
                    self.idle_timer = self.loop.call_later(IDLE_SECONDS,
                        lambda: self.loop.create_task(self._dispose_idle(lease)))
            self.condition.notify_all()

    async def _dispose(self, lease):
        if self.current is lease:
            self.current = None
        await lease.dispose(lease.resources)

    async def _dispose_idle(self, lease):
        async with self.condition:
            if self.current is lease and not lease.active:
                await self._dispose(lease)

    def run(self, factory, deadline):
        future = asyncio.run_coroutine_threadsafe(factory(self), self.loop)
        try:
            return future.result(timeout=max(0.001, deadline - time.monotonic()) + 0.5)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise TimeoutError() from None

    def close(self):
        if self.loop.is_closed():
            return
        async def cleanup():
            if self.idle_timer:
                self.idle_timer.cancel()
            if self.current:
                await self._dispose(self.current)
            # Shutdown is called after the dispatcher has drained. Finish any
            # remaining driver callbacks before closing its private event loop.
            remaining = asyncio.all_tasks() - {asyncio.current_task()}
            for task in remaining:
                task.cancel()
            if remaining:
                await asyncio.wait(remaining, timeout=0.2)
        try:
            asyncio.run_coroutine_threadsafe(cleanup(), self.loop).result(timeout=4)
        except concurrent.futures.TimeoutError:
            pass
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=1)
            if not self.thread.is_alive():
                for task in asyncio.all_tasks(self.loop):
                    task.cancel()
                    task._log_destroy_pending = False
                self.loop.close()


_runtime = None
_lock = threading.Lock()


def shared_runtime():
    global _runtime
    with _lock:
        if _runtime is None:
            _runtime = BrowserRuntime()
        return _runtime


def shutdown():
    global _runtime
    with _lock:
        runtime, _runtime = _runtime, None
    if runtime:
        runtime.close()


atexit.register(shutdown)
