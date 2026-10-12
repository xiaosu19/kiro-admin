"""Use real local sockets to exercise reads hidden inside HTTP framing parsers."""

import select
import socket
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app import aws_bills
from app.aws import AwsFailure


@contextmanager
def slow_wire_server(framing):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1)
    stopped, peer_closed = threading.Event(), threading.Event()
    errors = []

    def read_exact(connection, count):
        data = b""
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise EOFError()
            data += chunk
        return data

    def serve():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(1)
                if framing == "socks":
                    version, count = read_exact(connection, 2)
                    assert version == 5 and 0 in read_exact(connection, count)
                    connection.sendall(b"\x05\x00")
                    assert read_exact(connection, 4) == b"\x05\x01\x00\x03"
                    length = read_exact(connection, 1)[0]
                    assert read_exact(connection, length) == b"bills.proxy.invalid"
                    assert read_exact(connection, 2) == b"\x00\x50"
                    prefix, suffix = b"\x05\x00\x00\x03\xff", b""
                else:
                    request = b""
                    while not request.endswith(b"\r\n\r\n"):
                        request += read_exact(connection, 1)
                if framing == "headers":
                    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Slow: "
                    suffix = b"\r\n\r\nx"
                elif framing == "chunk":
                    prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;"
                    suffix = b"\r\nx\r\n0\r\n\r\n"
                connection.sendall(prefix)
                for _ in range(12):
                    # This delay is well below the read timeout. An absolute
                    # deadline must still interrupt readline's internal recv.
                    if select.select([connection], [], [], 0.03)[0]:
                        assert connection.recv(1) == b""
                        peer_closed.set()
                        return
                    if stopped.is_set():
                        return
                    connection.sendall(b"a")
                if not suffix:
                    return
                connection.sendall(suffix)
                if connection.recv(1) == b"":
                    peer_closed.set()
        except (BrokenPipeError, ConnectionResetError):
            peer_closed.set()
        except Exception as exc:
            errors.append(exc)

    server_thread = threading.Thread(target=serve, name="bills-slow-http-test")
    server_thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}/", peer_closed
    finally:
        stopped.set()
        listener.close()
        server_thread.join(timeout=2)
        assert not server_thread.is_alive()
        assert not errors


@pytest.mark.parametrize("framing", ["headers", "chunk", "socks"])
def test_absolute_deadline_interrupts_slow_framing_and_closes_connection(monkeypatch, framing):
    with slow_wire_server(framing) as (local_url, peer_closed):
        proxy = SimpleNamespace(url=local_url.replace("http://", "socks5h://").rstrip("/")) if framing == "socks" else None
        url = "http://bills.proxy.invalid/" if proxy else local_url
        monkeypatch.setattr(aws_bills, "TOTAL_TIMEOUT", 0.12)
        monkeypatch.setattr(aws_bills, "_allowed", lambda target, route, method: target == url and method == "GET")
        http = aws_bills._ConsoleHTTP(SimpleNamespace(proxy=proxy, _check_proxy=lambda: None))
        threads_before = set(threading.enumerate())
        started = time.monotonic()
        try:
            with pytest.raises(AwsFailure, match="超时"):
                http.request("GET", url)
            elapsed = time.monotonic() - started
        finally:
            http.close()
        assert elapsed < 0.26, f"The 0.12 s budget took {elapsed:.3f} s"
        assert peer_closed.wait(0.15), "The timed-out socket remained open"
        assert set(threading.enumerate()) <= threads_before, "Request left a worker thread behind"


def test_deadline_is_private_to_each_client_and_leaves_default_pools_unchanged(monkeypatch):
    from requests.adapters import HTTPAdapter
    from urllib3.contrib.socks import SOCKSProxyManager

    default = HTTPAdapter()
    direct_pools = default.poolmanager.pool_classes_by_scheme.copy()
    socks_pools = SOCKSProxyManager.pool_classes_by_scheme.copy()
    gateway = SimpleNamespace(proxy=None, _check_proxy=lambda: None)
    with slow_wire_server("headers") as (short_url, _), slow_wire_server("headers") as (long_url, _):
        monkeypatch.setattr(aws_bills, "_allowed", lambda target, route, method: target in {short_url, long_url} and method == "GET")
        monkeypatch.setattr(aws_bills, "TOTAL_TIMEOUT", 0.12)
        short = aws_bills._ConsoleHTTP(gateway)
        monkeypatch.setattr(aws_bills, "TOTAL_TIMEOUT", 1)
        long = aws_bills._ConsoleHTTP(gateway)
        try:
            with pytest.raises(AwsFailure, match="超时"):
                short.request("GET", short_url)
            status, _, body = long.request("GET", long_url)
            assert status == 200 and body == b"x"
            assert default.poolmanager.pool_classes_by_scheme == direct_pools
            assert SOCKSProxyManager.pool_classes_by_scheme == socks_pools
        finally:
            short.close()
            long.close()
            default.close()
