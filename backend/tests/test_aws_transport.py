"""Exercise real SOCKS5 authentication, remote DNS, TLS and AWS response parsing."""

import importlib.util
import json
import select
import socket
import socketserver
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import requests.adapters
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.awsrequest import AWSPreparedRequest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import aws


def transport_module():
    assert importlib.util.find_spec("app.aws_transport"), (
        "Per-client SOCKS transport is missing"
    )
    from app import aws_transport

    return aws_transport


def read_exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


@pytest.fixture
def socks_server(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("*.proxy.invalid")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "ca.pem", tmp_path / "key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_file, key_file)
    state = SimpleNamespace(
        connections=[], http=[], errors=[], reject=False, status=200, respond=None
    )

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                version, count = read_exact(self.request, 2)
                assert version == 5 and 2 in read_exact(self.request, count)
                self.request.sendall(b"\x05\x02")
                version, length = read_exact(self.request, 2)
                assert (
                    version == 1 and read_exact(self.request, length) == b"dummy-user"
                )
                length = read_exact(self.request, 1)[0]
                assert read_exact(self.request, length) == b"dummy-password"
                self.request.sendall(b"\x01\x00")
                version, command, _, atyp = read_exact(self.request, 4)
                assert version == 5 and command == 1 and atyp == 3
                host = read_exact(self.request, read_exact(self.request, 1)[0]).decode()
                port = int.from_bytes(read_exact(self.request, 2))
                state.connections.append((host, port, atyp))
                self.request.sendall(
                    b"\x05"
                    + (b"\x05" if state.reject else b"\x00")
                    + b"\x00\x01\x7f\x00\x00\x01\x01\xbb"
                )
                if state.reject:
                    return
                with tls.wrap_socket(self.request, server_side=True) as secure:
                    headers = b""
                    while not headers.endswith(b"\r\n\r\n"):
                        headers += read_exact(secure, 1)
                    values = dict(
                        line.split(":", 1)
                        for line in headers.decode().split("\r\n")[1:-2]
                    )
                    body = read_exact(secure, int(values.get("Content-Length", "0")))
                    state.http.append((headers, body))
                    if state.respond is not None:
                        state.respond(secure)
                        return
                    if host.startswith("sts."):
                        response = b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>test</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>sts-local</RequestId></ResponseMetadata></GetCallerIdentityResponse>'
                    else:
                        response = (
                            b'{"Password":"test-one-time", "Users":[], "Instances":[]}'
                        )
                    if state.status != 200:
                        response = b'{"__type":"AccessDeniedException", "message":"test-denied"}'
                    secure.sendall(
                        f"HTTP/1.1 {state.status} Test\r\n".encode()
                        + b"Content-Type: application/json\r\nLocation: https://redirect.proxy.invalid/\r\nx-amzn-requestid: local-test\r\nContent-Length: "
                        + str(len(response)).encode()
                        + b"\r\nConnection: close\r\n\r\n"
                        + response
                    )
            except Exception as exc:
                state.errors.append(type(exc).__name__)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(requests.adapters, "DEFAULT_CA_BUNDLE_PATH", str(cert_file))
    original_getaddrinfo = socket.getaddrinfo

    def local_only(host, *args, **kw):
        assert host in ("127.0.0.1", b"127.0.0.1"), (
            "Remote DNS or direct connection attempted"
        )
        return original_getaddrinfo(host, *args, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", local_only)
    state.proxy_url = (
        f"socks5h://dummy-user:dummy-password@127.0.0.1:{server.server_address[1]}"
    )
    yield state
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)
    assert not state.errors


@pytest.mark.parametrize(
    "service,host,method,kwargs,result_key",
    [
        ("sts", "sts.proxy.invalid", "get_caller_identity", {}, "Account"),
        (
            "identitystore",
            "identity.proxy.invalid",
            "list_users",
            {"IdentityStoreId": "d-1234567890"},
            "Users",
        ),
        ("sso-admin", "sso.proxy.invalid", "list_instances", {}, "Instances"),
    ],
)
def test_sdk_socks_remote_dns_preserves_signing_and_parses_response(
    socks_server, service, host, method, kwargs, result_key
):
    transport = transport_module()
    session = aws.make_session("TEST_ACCESS_KEY", "TEST_SECRET_KEY")
    client = session.client(
        service,
        region_name="us-east-1",
        endpoint_url=f"https://{host}",
        config=Config(retries={"max_attempts": 0}, proxies={}),
    )
    transport.configure_client_proxy(client, socks_server.proxy_url)
    result = getattr(client, method)(**kwargs)
    assert result_key in result
    assert socks_server.connections == [(host, 443, 3)]
    headers, body = socks_server.http[0]
    assert b"AWS4-HMAC-SHA256" in headers and b"TEST_ACCESS_KEY/" in headers
    assert b"dummy-password" not in headers and b"dummy-user" not in headers
    assert body
    client.close()


def test_signed_http_socks_remote_dns_preserves_signed_bytes(socks_server):
    transport_module()
    result, request_id = aws.signed_call(
        aws.make_session("TEST_ACCESS_KEY", "TEST_SECRET_KEY"),
        "us-east-1",
        "password.proxy.invalid",
        "userpool",
        "SWBUPService.UpdatePassword",
        {"UserId": "test-user", "PasswordMode": "OTP"},
        proxy_url=socks_server.proxy_url,
    )
    assert result["Password"] == "test-one-time" and request_id == "local-test"
    assert socks_server.connections == [("password.proxy.invalid", 443, 3)]
    headers, body = socks_server.http[0]
    assert b"/us-east-1/userpool/aws4_request" in headers
    assert json.loads(body) == {"UserId": "test-user", "PasswordMode": "OTP"}
    assert b"dummy-password" not in headers


def test_proxy_failure_never_falls_back_or_retries_and_hides_auth(socks_server):
    transport = transport_module()
    socks_server.reject = True
    session = aws.make_session("TEST_ACCESS_KEY", "TEST_SECRET_KEY")
    client = session.client(
        "sts",
        region_name="us-east-1",
        endpoint_url="https://sts.proxy.invalid",
        config=Config(retries={"max_attempts": 0}, proxies={}),
    )
    transport.configure_client_proxy(client, socks_server.proxy_url)
    with pytest.raises(BotoCoreError) as error:
        client.get_caller_identity()
    assert "dummy-password" not in str(error.value) and "dummy-user" not in str(
        error.value
    )
    with pytest.raises(aws.AwsFailure) as error:
        aws.signed_call(
            session,
            "us-east-1",
            "password.proxy.invalid",
            "q",
            "Service.CreateAssignment",
            {},
            proxy_url=socks_server.proxy_url,
        )
    assert "dummy-password" not in str(error.value) and "dummy-user" not in str(
        error.value
    )
    assert len(socks_server.connections) == 2
    assert not socks_server.http


def test_request_session_disables_environment_proxy_and_verifies_tls(monkeypatch):
    transport = transport_module()
    monkeypatch.setenv("HTTPS_PROXY", "http://bad-env.invalid:9999")
    with transport.request_session(None) as session:
        assert session.trust_env is False and session.verify is True
        assert not session.proxies
    with transport.request_session("socks5h://127.0.0.1:1080") as session:
        assert session.proxies == {
            "http": "socks5h://127.0.0.1:1080",
            "https": "socks5h://127.0.0.1:1080",
        }
        assert session.get_adapter("https://example.com").max_retries.total == 0


@pytest.mark.parametrize("framing", [None, "headers", "chunk"])
def test_bills_socket_deadline_preserves_authenticated_socks_remote_dns_and_tls(
    socks_server, monkeypatch, framing
):
    from app import aws_bills

    url = "https://billing.proxy.invalid/"
    monkeypatch.setattr(aws_bills, "_allowed", lambda target, route, method: target == url and method == "GET")
    peer_closed = threading.Event()
    if framing:
        monkeypatch.setattr(aws_bills, "TOTAL_TIMEOUT", 0.12)

        def respond(secure):
            try:
                if framing == "headers":
                    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Slow: "
                else:
                    prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;"
                secure.sendall(prefix)
                for _ in range(12):
                    if select.select([secure], [], [], 0.03)[0]:
                        assert secure.recv(1) == b""
                        peer_closed.set()
                        return
                    secure.sendall(b"a")
            except OSError:
                peer_closed.set()

        socks_server.respond = respond

    http = aws_bills._ConsoleHTTP(SimpleNamespace(
        proxy=SimpleNamespace(url=socks_server.proxy_url), _check_proxy=lambda: None,
    ))
    started = time.monotonic()
    try:
        if framing:
            with pytest.raises(aws.AwsFailure, match="超时"):
                http.request("GET", url)
            assert time.monotonic() - started < 0.26
            assert peer_closed.wait(0.15)
        else:
            status, _, body = http.request("GET", url)
            assert status == 200 and json.loads(body)["Instances"] == []
    finally:
        http.close()
    assert socks_server.connections == [("billing.proxy.invalid", 443, 3)]
    assert len(socks_server.http) == 1
    assert b"dummy-password" not in socks_server.http[0][0]


def test_sdk_wire_transport_does_not_reencode_already_signed_query(socks_server):
    transport = transport_module()
    client = aws.make_session("TEST", "TEST").client(
        "identitystore", region_name="us-east-1", config=Config(proxies={})
    )
    transport.configure_client_proxy(client, socks_server.proxy_url)
    request = AWSPreparedRequest(
        method="POST",
        url="https://identity.proxy.invalid/a%2Fb?x=%7E&x=%2F",
        headers={"Authorization": "AWS4-HMAC-SHA256 preserved", "Content-Length": "2"},
        body=b"{}",
        stream_output=False,
    )
    response = client._endpoint.http_session.send(request)
    assert response.content
    headers, body = socks_server.http[0]
    assert headers.startswith(b"POST /a%2Fb?x=%7E&x=%2F HTTP/1.1\r\n")
    assert body == b"{}"
    client.close()


@pytest.mark.parametrize("status", [302, 403, 500])
def test_sdk_preserves_aws_error_parsing_without_redirects_or_retries(
    socks_server, status
):
    transport = transport_module()
    socks_server.status = status
    client = aws.make_session("TEST", "TEST").client(
        "identitystore",
        region_name="us-east-1",
        endpoint_url="https://identity.proxy.invalid",
        config=Config(retries={"max_attempts": 0}, proxies={}),
    )
    transport.configure_client_proxy(client, socks_server.proxy_url)
    with pytest.raises(ClientError) as error:
        client.list_users(IdentityStoreId="d-1234567890")
    assert error.value.response["ResponseMetadata"]["HTTPStatusCode"] == status
    assert error.value.response["Error"]["Code"] == "AccessDeniedException"
    assert socks_server.connections == [("identity.proxy.invalid", 443, 3)]
    client.close()
