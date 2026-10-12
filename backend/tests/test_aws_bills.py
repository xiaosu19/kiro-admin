"""No live AWS calls: exercise the real signed client and bounded HTTP adapter."""
import gzip
import io
import json
from datetime import datetime, timezone
from decimal import Decimal
from email.message import Message
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

from app import aws
from app.database import SessionLocal
from app.models import AwsAccount

PAYER = "999999999999"
OTHER = "888888888888"
MONTH = "2026-10"
SECRET = "NEVER-ECHO-THIS-SECRET"
CONSOLE = "https://us-east-1.console.aws.amazon.com"
FEDERATION = "https://signin.aws.amazon.com/federation"


def bills():
    try:
        from app import aws_bills
    except ImportError:
        pytest.fail("The dedicated AWS Bills gateway has not been implemented")
    return aws_bills


@pytest.fixture(autouse=True)
def current_month(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is timezone.utc
            return cls(2026, 10, 11, tzinfo=timezone.utc)
    # Import inside fixture so the first red run explains the missing gateway.
    monkeypatch.setattr(bills(), "datetime", Clock)


def payload(amount=Decimal("123.45000000000000000001"), currency="USD", domain="billable_123"):
    return {"payerMap": {PAYER: {"amount": {"amount": amount, "currencyCode": currency}, "domainId": domain}},
            "blockingPayerList": []}


def test_decimal_precision_and_first_payer_default_never_sums_or_prefers_configured_account():
    data = payload()
    data["payerMap"][OTHER] = payload(Decimal("900"), "EUR", "proforma_abc")["payerMap"][PAYER]
    first = bills().parse_bill(data, MONTH)
    assert first["amount"] == "123.45000000000000000001"
    assert first["payer_id"] == PAYER
    assert first["available_payers"] == [PAYER, OTHER]
    assert first["currency"] == "USD" and first["source"] == "aws_bills_console"
    assert first["estimated"] is True and first["billing_kind"] == "billable"
    assert (first["period_start"], first["period_end"]) == ("2026-10-01", "2026-11-01")
    assert first["retrieved_at"] == "2026-10-11T00:00:00Z"
    assert "updated_at" not in first
    second = bills().parse_bill(data, MONTH, OTHER)
    assert second["amount"] == "900" and second["currency"] == "EUR"
    assert second["payer_id"] == OTHER and second["billing_kind"] == "proforma"


@pytest.mark.parametrize("bad", [None, [], {}, {"payerMap": {}, "blockingPayerList": []},
    {**payload(), "blockingPayerList": [PAYER]}, {**payload(), "blockingPayerList": {}},
    payload(Decimal("NaN")), payload(Decimal("Infinity")), payload(True), payload("oops"),
    payload("1e99999"), payload("1e-99999"), payload(0.1), payload(currency="usd"),
    payload(currency="<script>"), payload(currency="ZZZ"), payload(domain=None),
    {"payerMap": {"invalid": payload()["payerMap"][PAYER]}, "blockingPayerList": []},
    {"payerMap": {PAYER: None}, "blockingPayerList": []}])
def test_empty_blocked_malformed_and_nonfinite_bill_is_unavailable(bad):
    with pytest.raises(aws.AwsFailure):
        bills().parse_bill(bad, MONTH)


def test_zero_and_negative_totals_are_real_values_and_selected_payer_must_exist():
    assert bills().parse_bill(payload(Decimal("0.00")), MONTH)["amount"] == "0.00"
    assert bills().parse_bill(payload(Decimal("-0.05")), MONTH)["amount"] == "-0.05"
    with pytest.raises(ValueError):
        bills().parse_bill(payload(), MONTH, OTHER)


@pytest.mark.parametrize("month", ["2026-09", "2026-11", "2026-1", "2026-13", "0000-01", "9999-12"])
def test_only_the_current_utc_month_is_valid(month):
    with pytest.raises(ValueError):
        bills().current_period(month)


def gateway():
    with SessionLocal() as db:
        return aws.AwsGateway(db.get(AwsAccount, 1))


def response(body=b"", status=200, headers=None):
    headers = headers or {}
    msg = Message()
    for key, value in headers.items():
        msg[key] = value
    raw = HTTPResponse(body=io.BytesIO(body), headers=headers, preload_content=False,
                       original_response=SimpleNamespace(msg=msg, isclosed=lambda: False))
    result = requests.Response()
    result.status_code, result.headers, result.raw = status, requests.structures.CaseInsensitiveDict(headers), raw
    return result


def sts_xml(account="123456789012"):
    return (f'<GetFederationTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            f'<GetFederationTokenResult><FederatedUser><Arn>arn:aws:sts::{account}:federated-user/KiroBillsReadOnlyCheck</Arn>'
            '<FederatedUserId>test</FederatedUserId></FederatedUser><Credentials>'
            f'<AccessKeyId>{SECRET}</AccessKeyId><SecretAccessKey>{SECRET}</SecretAccessKey><SessionToken>{SECRET}</SessionToken>'
            '<Expiration>2026-10-11T01:00:00Z</Expiration></Credentials>'
            '</GetFederationTokenResult></GetFederationTokenResponse>').encode()


def sequence():
    return [response(sts_xml()), response(json.dumps({"SigninToken": SECRET}).encode()),
            response(status=302, headers={"Location": CONSOLE + "/billing/home?first=1", "Set-Cookie": "signin=secret; Secure; Path=/"}),
            response(status=302, headers={"Location": "https://signin.aws.amazon.com/oauth?one=1", "Set-Cookie": "billing=secret; Secure; Path=/billing"}),
            response(status=302, headers={"Location": CONSOLE + "/billing/home?second=1"}),
            response(f'<html><input value="{SECRET}" id="xsrfToken"></html>'.encode()),
            response(b'{"payerMap":{"999999999999":{"amount":{"currencyCode":"USD","amount":123.45000000000000000001},"domainId":"proforma_abc"}},"blockingPayerList":[]}')]


def wire(monkeypatch, responses, on_send=None):
    sent, used = [], []
    def send(self, prepared, **kwargs):
        sent.append((prepared, kwargs))
        if on_send:
            on_send(prepared, kwargs)
        current = responses.pop(0)
        if isinstance(current, Exception):
            raise current
        current.url, current.request = prepared.url, prepared
        used.append(current)
        return current
    monkeypatch.setattr(HTTPAdapter, "send", send)
    return sent, used


def test_full_sts_federation_cookie_xsrf_flow_uses_guarded_proxy_and_exact_bill_protocol(monkeypatch):
    g, checks = gateway(), []
    g.proxy = SimpleNamespace(url="socks5h://user:pass@127.0.0.1:1080")
    monkeypatch.setattr(g, "_check_proxy", lambda: checks.append(True))
    monkeypatch.setenv("HTTPS_PROXY", "http://MUST-NOT-USE:9999")
    sent, used = wire(monkeypatch, sequence())
    value = g.monthly_cost(MONTH)
    assert value["amount"] == "123.45000000000000000001" and value["billing_kind"] == "proforma"
    assert len(sent) == len(checks) == 7
    for req, kw in sent:
        assert kw["verify"] is True and kw["stream"] is True
        assert kw["proxies"] == {"http": g.proxy.url, "https": g.proxy.url}
    sts = parse_qs(sent[0][0].body.decode() if isinstance(sent[0][0].body, bytes) else sent[0][0].body)
    assert sts["Action"] == ["GetFederationToken"] and sts["DurationSeconds"] == ["900"]
    policy = json.loads(sts["Policy"][0])
    assert policy["Statement"][0]["Resource"] == "*"
    assert set(policy["Statement"][0]["Action"]) == set(bills().POLICY_ACTIONS)
    token_body = parse_qs(sent[1][0].body)
    assert token_body["Action"] == ["getSigninToken"]
    assert set(json.loads(token_body["Session"][0])) == {"sessionId", "sessionKey", "sessionToken"}
    assert sent[4][0].headers["Cookie"] == "signin=secret"
    assert sent[5][0].headers["Cookie"] == "billing=secret"
    last = sent[-1][0]
    assert urlsplit(last.url).path == "/billing/rest/v1.0/bill/completebill"
    assert parse_qs(urlsplit(last.url).query) == {"year": ["2026"], "month": ["10"], "groupBy": ["ServiceProvider"]}
    assert last.headers["x-awsbc-xsrf-token"] == SECRET
    assert all(item.raw.closed for item in used)


@pytest.mark.parametrize("account", ["111111111111", "bad"])
def test_wrong_federated_account_stops_before_any_console_request(monkeypatch, account):
    sent, used = wire(monkeypatch, [response(sts_xml(account))])
    with pytest.raises(aws.AwsFailure, match="账号"):
        gateway().monthly_cost(MONTH)
    assert len(sent) == 1 and used[0].raw.closed


@pytest.mark.parametrize("target", ["http://signin.aws.amazon.com/federation", "https://evil.example/",
    "https://signin.aws.amazon.com.evil.example/oauth", "https://us-west-2.console.aws.amazon.com/billing/home",
    CONSOLE + "/billing/rest/v1.0/account", CONSOLE + "/billing/home/../account", CONSOLE + "/billing/%68ome",
    CONSOLE + ":444/billing/home", "https://user:pass@signin.aws.amazon.com/oauth", "https://signin.aws.amazon.com/console"])
def test_redirect_host_and_route_allowlist_prevents_following_unknown_destinations(monkeypatch, target):
    rows = sequence()[:3]
    rows[-1].headers["Location"] = target
    sent, used = wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure):
        gateway().monthly_cost(MONTH)
    assert len(sent) == 3 and all(item.raw.closed for item in used)


def test_redirect_body_is_never_implicitly_consumed_and_loop_is_bounded(monkeypatch):
    rows = sequence()[:3]
    rows[-1].headers["Location"] = CONSOLE + "/billing/home?loop=1"
    class MustNotRead:
        _original_response = None
        closed = False
        def read(self, *a, **kw):
            raise AssertionError("redirect body consumed")
        read1 = read
        def close(self):
            self.closed = True
        def release_conn(self):
            pass
    rows[-1].raw = MustNotRead()
    rows.extend(response(status=302, headers={"Location": CONSOLE + "/billing/home?loop=1"})
                for _ in range(bills().MAX_REDIRECTS))
    sent, used = wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure, match="跳转"):
        gateway().monthly_cost(MONTH)
    assert len(sent) == bills().MAX_REDIRECTS + 3 and all(item.raw.closed for item in used)


@pytest.mark.parametrize("stage", [0, 1, 5, 6])
def test_encoded_and_decompressed_response_body_sizes_are_bounded(monkeypatch, stage):
    monkeypatch.setattr(bills(), "MAX_BODY_BYTES", 1024)
    for compress in (False, True):
        rows = sequence()[:stage + 1]
        data = b"x" * 2048
        rows[-1] = response(gzip.compress(data) if compress else data,
                            headers={"Content-Encoding": "gzip"} if compress else {})
        sent, used = wire(monkeypatch, rows)
        with pytest.raises(aws.AwsFailure):
            gateway().monthly_cost(MONTH)
        assert len(sent) == stage + 1 and all(item.raw.closed for item in used)


@pytest.mark.parametrize("body", [b"<html>no token</html>", b'<input id="xsrfToken" value="">',
    b'<input id="xsrfToken" value="one"><input id="xsrfToken" value="two">'])
def test_missing_or_ambiguous_xsrf_is_unavailable(monkeypatch, body):
    rows = sequence()[:6]
    rows[-1] = response(body)
    sent, used = wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure):
        gateway().monthly_cost(MONTH)
    assert len(sent) == 6 and all(item.raw.closed for item in used)


@pytest.mark.parametrize("stage", [0, 1, 6])
@pytest.mark.parametrize("failure", [requests.Timeout(SECRET), requests.ConnectionError(SECRET), requests.exceptions.SSLError(SECRET)])
def test_transport_errors_are_static_and_secret_safe(monkeypatch, stage, failure):
    rows = sequence()[:stage] + [failure]
    sent, used = wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure) as raised:
        gateway().monthly_cost(MONTH)
    assert SECRET not in str(raised.value) and "http" not in str(raised.value)
    assert len(sent) == stage + 1 and all(item.raw.closed for item in used)


def test_access_denied_explains_sts_and_billing_iam_requirements_without_raw_error(monkeypatch):
    body = f'<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Code>AccessDenied</Code><Message>{SECRET}</Message></Error></ErrorResponse>'.encode()
    wire(monkeypatch, [response(body, 403)])
    with pytest.raises(aws.AwsFailure) as raised:
        gateway().monthly_cost(MONTH)
    assert "sts:GetFederationToken" in str(raised.value) and SECRET not in str(raised.value)
    rows = sequence()
    rows[-1] = response(SECRET.encode(), 403)
    wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure) as raised:
        gateway().monthly_cost(MONTH)
    assert "Billing" in str(raised.value) and SECRET not in str(raised.value)


def test_proxy_revocation_stops_next_wire_and_total_budget_stops_slow_flow(monkeypatch):
    g, checks = gateway(), []
    def guard():
        checks.append(1)
        if len(checks) == 4:
            raise aws.AwsFailure("代理已停用")
    monkeypatch.setattr(g, "_check_proxy", guard)
    sent, used = wire(monkeypatch, sequence())
    with pytest.raises(aws.AwsFailure, match="代理"):
        g.monthly_cost(MONTH)
    assert len(sent) == 3 and all(item.raw.closed for item in used)
    clock = [0]
    monkeypatch.setattr(bills().time, "monotonic", lambda: clock[0])
    def delay(*args):
        clock[0] += bills().TOTAL_TIMEOUT + 1
    sent, used = wire(monkeypatch, sequence(), delay)
    with pytest.raises(aws.AwsFailure, match="超时"):
        gateway().monthly_cost(MONTH)
    assert len(sent) == 1 and used[0].raw.closed


def test_extreme_decimal_exponent_is_a_static_unavailable_error():
    with pytest.raises(aws.AwsFailure):
        bills().parse_bill(payload(Decimal("1e1000000")), MONTH)


@pytest.mark.parametrize("token", [SECRET + "\r\nInjected: value", SECRET + "\u0100", " " + SECRET])
def test_malformed_xsrf_never_exposes_header_contents_or_sends_bill(monkeypatch, token):
    rows = sequence()[:6]
    rows[-1] = response(f'<input id="xsrfToken" value="{token}">'.encode())
    sent, used = wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure) as raised:
        gateway().monthly_cost(MONTH)
    assert SECRET not in str(raised.value)
    assert len(sent) == 6 and all(item.raw.closed for item in used)


@pytest.mark.parametrize("body", [b"not json", b'{"payerMap":{},"payerMap":{}}', b'[' * 1500])
def test_invalid_json_and_duplicate_fields_are_static_unavailable(monkeypatch, body):
    rows = sequence()
    rows[-1] = response(body)
    wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure):
        gateway().monthly_cost(MONTH)


@pytest.mark.parametrize("failure", [False, True])
def test_http_session_and_sts_client_close_on_success_and_error_with_environment_ignored(monkeypatch, failure):
    g, clients_closed, sessions = gateway(), [], []
    original = g._client
    def client(*args, **kw):
        value = original(*args, **kw)
        close = value.close
        def closed():
            clients_closed.append(True)
            close()
        value.close = closed
        return value
    monkeypatch.setattr(g, "_client", client)
    original_session = bills().request_session
    def session(*args, **kw):
        value = original_session(*args, **kw)
        close = value.close
        value.was_closed = False
        def closed():
            value.was_closed = True
            close()
        value.close = closed
        sessions.append(value)
        return value
    monkeypatch.setattr(bills(), "request_session", session)
    monkeypatch.setenv("HTTPS_PROXY", "http://MUST-NOT-USE:9999")
    rows = sequence()
    if failure:
        rows[-1] = response(b"denied", 403)
    sent, used = wire(monkeypatch, rows)
    if failure:
        with pytest.raises(aws.AwsFailure):
            g.monthly_cost(MONTH)
    else:
        g.monthly_cost(MONTH)
    assert clients_closed == [True] and len(sessions) == 1
    assert sessions[0].was_closed and not sessions[0].cookies
    assert all(kw["proxies"] == {} and kw["verify"] is True for _, kw in sent)
    assert all(item.raw.closed for item in used)


def test_sts_parser_error_never_leaks_upstream_body(monkeypatch):
    sent, used = wire(monkeypatch, [response(("not xml " + SECRET).encode())])
    with pytest.raises(aws.AwsFailure) as raised:
        gateway().monthly_cost(MONTH)
    assert SECRET not in str(raised.value) and len(sent) == 1 and used[0].raw.closed


def test_unique_redirect_chain_has_a_finite_hop_limit(monkeypatch):
    rows = sequence()[:2] + [response(status=302, headers={"Location": CONSOLE + f"/billing/home?hop={i}"})
                              for i in range(bills().MAX_REDIRECTS + 1)]
    sent, used = wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure, match="上限"):
        gateway().monthly_cost(MONTH)
    assert len(sent) == bills().MAX_REDIRECTS + 3 and all(item.raw.closed for item in used)


@pytest.mark.parametrize("fragment", ["", "#/bills", "#/bills/", "#bills"])
def test_oauth_can_return_to_same_billing_home_with_new_cookies_and_bills_fragment(monkeypatch, fragment):
    rows = sequence()
    rows[4] = response(status=302, headers={"Location": rows[2].headers["Location"] + fragment,
                       "Set-Cookie": "oauth=arrived; Domain=.aws.amazon.com; Path=/; Secure"})
    sent, used = wire(monkeypatch, rows)
    result = gateway().monthly_cost(MONTH)
    assert result["amount"] == "123.45000000000000000001"
    assert sent[3][0].url == sent[5][0].url
    assert "oauth=arrived" in sent[5][0].headers["Cookie"]
    assert "billing=secret" in sent[5][0].headers["Cookie"]
    assert all(not urlsplit(req.url).fragment for req, _ in sent)
    assert len(sent) == 7 and all(item.raw.closed for item in used)


@pytest.mark.parametrize("target", [CONSOLE + "/billing/home#/other", FEDERATION + "#/bills",
    "https://signin.aws.amazon.com/oauth#/bills", "https://evil.example/billing/home#/bills",
    CONSOLE + "/billing/rest/v1.0/account#/bills"])
def test_only_exact_bills_fragments_on_the_allowed_console_home_are_accepted(monkeypatch, target):
    rows = sequence()[:3]
    rows[-1].headers["Location"] = target
    sent, used = wire(monkeypatch, rows)
    with pytest.raises(aws.AwsFailure):
        gateway().monthly_cost(MONTH)
    assert len(sent) == 3 and all(item.raw.closed for item in used)


@pytest.mark.parametrize("failure", [False, True])
def test_debug_logs_never_capture_federation_session_url_headers_or_failure_trace(monkeypatch, caplog, failure):
    import logging
    for name in ("botocore", "urllib3", "requests"):
        caplog.set_level(logging.DEBUG, logger=name)
    caplog.set_level(logging.DEBUG)
    secrets = ["TEMP-ACCESS-SENTINEL", "TEMP-SECRET-SENTINEL", "TEMP-SESSION-SENTINEL",
               "SIGNIN-SENTINEL", "XSRF-SENTINEL", "COOKIE-SENTINEL"]
    rows = sequence()
    xml = sts_xml().decode()
    for value in secrets[:3]:
        xml = xml.replace(SECRET, value, 1)
    rows[0] = response(xml.encode())
    rows[1] = response(json.dumps({"SigninToken": secrets[3]}).encode())
    rows[2] = response(status=302, headers={**rows[2].headers, "Set-Cookie": f"signin={secrets[5]}; Secure; Path=/"})
    rows[5] = response(f'<input id="xsrfToken" value="{secrets[4]}">'.encode())
    if failure:
        rows[-1] = response(b"denied", 403)
    def debug_wire(prepared, options):
        # The adapter is mocked, so emit the records that requests/urllib3 would
        # create at this real wire boundary; botocore's parser logs remain real.
        logging.getLogger("urllib3.connectionpool").debug("%s %s", prepared.method, prepared.url)
        logging.getLogger("requests.transport").debug("headers=%s body=%s", prepared.headers, prepared.body)
        if failure and urlsplit(prepared.url).path == bills().BILL_PATH:
            try:
                raise RuntimeError(secrets[4])
            except RuntimeError:
                logging.getLogger("urllib3.connectionpool").exception("wire failed %s", secrets[5])
    wire(monkeypatch, rows, debug_wire)
    if failure:
        with pytest.raises(aws.AwsFailure):
            gateway().monthly_cost(MONTH)
    else:
        gateway().monthly_cost(MONTH)
    protected = caplog.text
    for secret in secrets + ["TEST_ACCESS_KEY"]:
        assert secret not in protected
    assert any(record.name == "botocore.parsers" for record in caplog.records)
    assert any(record.name == "urllib3.connectionpool" for record in caplog.records)
    assert all(record.exc_info is None for record in caplog.records)
    logging.getLogger("urllib3.connectionpool").debug("ordinary-after-request")
    assert "ordinary-after-request" in caplog.text


def test_sensitive_logging_is_isolated_between_overlapping_calls_and_other_threads(monkeypatch, caplog):
    import logging
    import threading
    from concurrent.futures import ThreadPoolExecutor
    for name in ("botocore", "urllib3", "requests"):
        caplog.set_level(logging.DEBUG, logger=name)
    caplog.set_level(logging.DEBUG)
    entered = [threading.Event(), threading.Event()]
    release = [threading.Event(), threading.Event()]
    local = threading.local()
    def send(self, prepared, **kw):
        if not hasattr(local, "rows"):
            local.rows = sequence()
            entered[local.index].set()
            assert release[local.index].wait(5)
        logging.getLogger("urllib3.connectionpool").debug("sensitive wire %s %s", SECRET, prepared.url)
        value = local.rows.pop(0)
        value.url, value.request = prepared.url, prepared
        return value
    monkeypatch.setattr(HTTPAdapter, "send", send)
    def run(index):
        local.index = index
        return gateway().monthly_cost(MONTH)
    before_levels = {name: logging.getLogger(name).level for name in ("botocore", "urllib3", "requests")}
    with ThreadPoolExecutor(2) as pool:
        first, second = pool.submit(run, 0), pool.submit(run, 1)
        try:
            assert all(event.wait(5) for event in entered)
            logging.getLogger("urllib3.connectionpool").debug("ordinary-concurrent-request")
            release[0].set()
            assert first.result()["currency"] == "USD"
            logging.getLogger("botocore.parsers").debug("ordinary-between-requests")
            release[1].set()
            assert second.result()["currency"] == "USD"
        finally:
            for event in release:
                event.set()
    assert SECRET not in caplog.text
    assert "ordinary-concurrent-request" in caplog.text and "ordinary-between-requests" in caplog.text
    assert before_levels == {name: logging.getLogger(name).level for name in before_levels}


def test_log_guard_redacts_before_a_later_wrapped_record_factory_sees_payload(monkeypatch, caplog):
    import logging
    from functools import wraps
    caplog.set_level(logging.DEBUG)
    bills()._install_log_guard()
    previous = logging.getLogRecordFactory()
    observed = []
    @wraps(previous)
    def custom_factory(*args, **kwargs):
        observed.append(repr((args, kwargs)))
        return previous(*args, **kwargs)
    logging.setLogRecordFactory(custom_factory)
    try:
        wire(monkeypatch, sequence(), lambda prepared, options: logging.getLogger("urllib3.connectionpool").debug("wire %s", SECRET))
        gateway().monthly_cost(MONTH)
        assert SECRET not in "\n".join(observed)
        logging.getLogger("urllib3.connectionpool").debug("ordinary-custom-factory")
        assert "ordinary-custom-factory" in "\n".join(observed)
    finally:
        logging.setLogRecordFactory(previous)
