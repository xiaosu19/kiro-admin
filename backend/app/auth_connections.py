"""Bounded native-login keep-alive pools; never retain cookies or headers.

Each checkout owns a transport exclusively. The encrypted workflow's random
operation ID and exact proxy bind a pool to one login, even when successive
durable steps run on different threads. Authority is still checked at every send.
"""

import atexit
import time
from collections import OrderedDict
from contextlib import contextmanager
from threading import Lock

from requests.adapters import HTTPAdapter

IDLE_SECONDS = 30
MAX_IDLE_FLOWS = 20
_idle = OrderedDict()
_lock = Lock()


def prune(*, all=False):
    closed = []
    with _lock:
        instant = time.monotonic()
        for key, (since, adapter) in list(_idle.items()):
            if all or instant - since >= IDLE_SECONDS:
                closed.append(adapter)
                del _idle[key]
    for adapter in closed:
        adapter.close()


@contextmanager
def reuse_connections(session, *, flow_id, proxy_url):
    prune()
    key = (flow_id, proxy_url)
    with _lock:
        found = _idle.pop(key, None)
    adapter = found[1] if found else HTTPAdapter(
        pool_connections=4, pool_maxsize=1, max_retries=0, pool_block=True)
    session.adapters['https://'].close()
    session.mount('https://', adapter)
    succeeded = False
    try:
        yield session
        succeeded = True
    finally:
        # Session.close must not destroy a healthy borrowed connection pool.
        session.adapters.pop('https://', None)
        session.close()
        closed = []
        if succeeded:
            with _lock:
                old = _idle.pop(key, None)
                if old:
                    closed.append(old[1])
                _idle[key] = (time.monotonic(), adapter)
                while len(_idle) > MAX_IDLE_FLOWS:
                    closed.append(_idle.popitem(last=False)[1][1])
        else:
            closed.append(adapter)
        for value in closed:
            value.close()


atexit.register(prune, all=True)
