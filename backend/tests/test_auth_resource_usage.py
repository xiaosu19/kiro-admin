"""Connection isolation and bounded DB work for large authentication batches."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, select

from app import auth_connections
from app.aws_transport import request_session
from app.database import SessionLocal, engine
from app.models import AuthBatch, AuthJob, AwsAccount, RecordOperation
from test_auth_batches import admission, record
from test_aws_transport import read_exact, socks_server


@pytest.fixture(autouse=True)
def clear_pools():
    auth_connections.prune(all=True)
    yield
    auth_connections.prune(all=True)


def test_keepalive_crosses_worker_threads_without_carrying_cookies_or_headers(socks_server):
    second_headers = []

    def respond(sock):
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
                     b'Set-Cookie: private=first-user; Path=/\r\nConnection: keep-alive\r\n\r\n{}')
        headers = b''
        while not headers.endswith(b'\r\n\r\n'):
            headers += read_exact(sock, 1)
        second_headers.append(headers)
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')

    socks_server.respond = respond

    def request(first=False):
        with auth_connections.reuse_connections(request_session(socks_server.proxy_url),
                flow_id='one-login', proxy_url=socks_server.proxy_url) as session:
            if first:
                session.headers['Authorization'] = 'Bearer first-request-only'
            response = session.get('https://login.proxy.invalid/', timeout=3, allow_redirects=False)
            assert response.json() == {}
            if first:
                assert session.cookies.get('private') == 'first-user'
            else:
                assert not list(session.cookies)

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(request, True).result()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(request).result()
    assert len(socks_server.connections) == 1  # One SOCKS + TLS handshake, two requests.
    assert b'Cookie:' not in second_headers[0]
    assert b'Authorization:' not in second_headers[0]


def test_flow_proxy_isolation_and_bounded_idle_eviction(monkeypatch):
    monkeypatch.setattr(auth_connections, 'MAX_IDLE_FLOWS', 2)
    seen, closed = [], []
    for flow, proxy in [('a', None), ('b', None), ('a', 'socks5h://127.0.0.1:9')]:
        with auth_connections.reuse_connections(request_session(proxy), flow_id=flow, proxy_url=proxy) as session:
            adapter = session.adapters['https://']
            seen.append(adapter)
            monkeypatch.setattr(adapter, 'close', lambda value=adapter: closed.append(value))
    assert len({id(a) for a in seen}) == 3
    assert closed == seen[:1]
    assert len(auth_connections._idle) == 2
    auth_connections.prune(all=True)
    assert closed == seen


def test_failed_request_does_not_leave_idle_pool():
    with pytest.raises(RuntimeError):
        with auth_connections.reuse_connections(request_session(), flow_id='bad', proxy_url=None):
            raise RuntimeError('local fixture failure')
    assert not auth_connections._idle


def test_twenty_login_flows_retain_their_own_connections_between_steps():
    adapters = {}
    for round_number in range(2):
        for flow in range(20):
            with auth_connections.reuse_connections(request_session(),
                    flow_id=str(flow), proxy_url=None) as session:
                adapter = session.adapters['https://']
                if round_number:
                    assert adapter is adapters[flow]
                else:
                    adapters[flow] = adapter
    assert len({id(adapter) for adapter in adapters.values()}) == 20


def test_idle_pool_expires(monkeypatch):
    instant = [10.0]
    monkeypatch.setattr(auth_connections.time, 'monotonic', lambda: instant[0])
    with auth_connections.reuse_connections(request_session(), flow_id='one', proxy_url=None):
        pass
    instant[0] += auth_connections.IDLE_SECONDS
    auth_connections.prune()
    assert not auth_connections._idle


def test_gateway_http_steps_do_not_construct_sdk_or_decrypt_aws_key(monkeypatch):
    from app import aws
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        db.expunge(account)
    called = []
    monkeypatch.setattr(aws, 'make_session', lambda **kwargs: called.append(True) or object())
    gateway = aws.AwsGateway(account)
    assert called == []
    assert gateway.session is gateway.session
    assert called == [True]
    gateway.close()


def test_finish_batch_uses_constant_queries_and_observes_uncommitted_last_step(alice):
    from app.auth_batches import finish_batch
    batch_id = admission(alice, [record() for _ in range(60)]).json()['id']
    with SessionLocal() as db:
        operations = list(db.scalars(select(RecordOperation).join(AuthJob, AuthJob.id == RecordOperation.id)
                                    .where(AuthJob.batch_id == batch_id)))
        for operation in operations[:-1]:
            operation.state = 'completed'
        db.commit()
    statements = []
    def count(_conn, _cursor, sql, *_):
        if sql.lstrip().upper().startswith('SELECT'):
            statements.append(sql)
    with SessionLocal() as db:
        batch = db.get(AuthBatch, batch_id)
        event.listen(engine, 'before_cursor_execute', count)
        try:
            finish_batch(db, batch)
            assert batch.completed_at is None
            assert len(statements) == 1
            last = db.get(RecordOperation, operations[-1].id)
            last.state = 'completed'
            statements.clear()
            finish_batch(db, batch)
            assert batch.completed_at is not None
            assert batch.download_expires_at is not None
            assert len(statements) <= 3
        finally:
            event.remove(engine, 'before_cursor_execute', count)


def test_expiry_maintenance_does_not_load_sixty_unchallenged_workflows(alice):
    from app.auth_jobs import expire_batches
    admission(alice, [record() for _ in range(60)])
    statements = []
    def count(_conn, _cursor, sql, *_):
        if sql.lstrip().upper().startswith('SELECT'):
            statements.append(sql)
    event.listen(engine, 'before_cursor_execute', count)
    try:
        expire_batches()
    finally:
        event.remove(engine, 'before_cursor_execute', count)
    assert len(statements) <= 6


@pytest.mark.parametrize('change', ['binding', 'proxy', 'session', 'cancel'])
def test_pasted_guard_limits_reads_without_caching_authority(alice, change):
    from app import external_auth_worker as worker
    from app.external_auth_models import ExternalExportItem
    from app.models import Binding, Proxy, User
    from app.security import encrypt
    from test_external_auth_batches import admit
    from test_external_managed_login import managed_record

    managed_record()
    with SessionLocal() as db:
        proxy = Proxy(name='guard-budget', host='127.0.0.1', port=1080,
                      auth_encrypted=encrypt({'username': 'proxy', 'password': 'Synthetic9!'}))
        db.add(proxy)
        db.flush()
        db.get(AwsAccount, 1).proxy_id = proxy.id
        proxy_id = proxy.id
        db.commit()
    batch = admit(alice).json()
    item_id = batch['items'][0]['id']
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, item_id)
        item.state, item.lease_token = 'running', 'guard-lease'
        db.commit()

    statements = []
    def count(_conn, _cursor, sql, *_):
        if sql.lstrip().upper().startswith('SELECT'):
            statements.append(sql)
    event.listen(engine, 'before_cursor_execute', count)
    try:
        for _ in range(2):
            statements.clear()
            worker.authorize(item_id, 'guard-lease')
            # The proxy keeps its additional forced refresh before every send.
            assert len(statements) <= 3
    finally:
        event.remove(engine, 'before_cursor_execute', count)
    with SessionLocal() as db:
        if change == 'binding':
            db.delete(db.get(Binding, (2, 1)))
        elif change == 'proxy':
            db.get(Proxy, proxy_id).enabled = False
        elif change == 'session':
            db.get(User, 2).session_version += 1
        else:
            db.get(ExternalExportItem, item_id).cancel_requested = True
        db.commit()
    with pytest.raises(worker.Revoked):
        worker.authorize(item_id, 'guard-lease')
