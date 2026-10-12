"""Current AWS Bills console total, through an ephemeral, read-only federation.

The console protocol is internal to AWS (verified 2026-10-10). Never persist or
log federation credentials, URLs, cookies, XSRF values, or upstream bodies.
"""

import io
import json
import logging
import re
import time
import zlib
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
from threading import Lock
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from botocore.awsrequest import AWSResponse
from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import HTTPError
from urllib3.util import Timeout

from .aws import AwsFailure
from .aws_bills_transport import DeadlineAdapter
from .aws_report_gateway import month_period
from .aws_transport import request_session

CONSOLE = "https://us-east-1.console.aws.amazon.com"
FEDERATION = "https://signin.aws.amazon.com/federation"
DESTINATION = CONSOLE + "/billing/home?region=us-east-1&state=hashArgs%23%2Fbills"
BILL_PATH = "/billing/rest/v1.0/bill/completebill"
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
MAX_REDIRECTS = 8
TOTAL_TIMEOUT = 90
POLICY_ACTIONS = (
    "account:GetAccountInformation", "billing:GetBillingData", "billing:GetBillingDetails",
    "billing:GetIAMAccessPreference", "consolidatedbilling:GetAccountBillingRole",
    "invoicing:ListInvoiceSummaries",
)
# ISO currency identifiers accepted by the amount display; unknown identifiers
# are unavailable rather than being formatted as an invented monetary unit.
CURRENCIES = frozenset("""
AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL BSD BTN BWP BYN BZD
CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL
GHS GIP GMD GNF GTQ GYD HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD
KYD KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR MZN NAD NGN
NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SLL
SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD USN UYI UYU UYW UZS VED VES
VND VUV WST XAF XCD XOF XPF YER ZAR ZMW ZWG ZWL
""".split())
UNAVAILABLE = "AWS Bills 响应不可用或格式异常，请重试并检查 Billing IAM 访问权限"


# Library DEBUG logs can contain entire STS responses and federation URLs. A
# single factory guard redacts records before *any* handler/custom factory sees
# them. ContextVar limits it to this operation; logger levels are never changed.
_sensitive_logs = ContextVar("aws_bills_sensitive_logs", default=False)
_log_factory_lock = Lock()
_guarded_factory = None


def _install_log_guard():
    global _guarded_factory
    with _log_factory_lock:
        previous = logging.getLogRecordFactory()
        if previous is _guarded_factory:
            return

        def guarded(name, level, pathname, lineno, msg, args, exc_info, func=None, sinfo=None, **kwargs):
            if _sensitive_logs.get() and name.split(".", 1)[0] in {"botocore", "boto3", "urllib3", "requests", "socks"}:
                msg, args, exc_info, sinfo = "AWS Bills sensitive transport diagnostics redacted", (), None, None
            return previous(name, level, pathname, lineno, msg, args, exc_info, func, sinfo, **kwargs)

        _guarded_factory = guarded
        logging.setLogRecordFactory(guarded)


@contextmanager
def _protected_transport_logs():
    _install_log_guard()
    token = _sensitive_logs.set(True)
    try:
        yield
    finally:
        _sensitive_logs.reset(token)


def current_period(month=None):
    current = datetime.now(timezone.utc).strftime("%Y-%m")
    if month is not None and month != current:
        raise ValueError("AWS Bills 仅支持当前 UTC 月份")
    return month_period(current)


def validate_payer(payer_id):
    if payer_id is not None and (not isinstance(payer_id, str) or not re.fullmatch(r"[0-9]{12}", payer_id)):
        raise ValueError("付款账号需要有效的 12 位 AWS 账号 ID")


def parse_bill(data, month, payer_id=None):
    start, end = current_period(month)
    validate_payer(payer_id)
    try:
        if (not isinstance(data, dict) or data.get("blockingPayerList") != []
                or not isinstance(data.get("payerMap"), dict) or not 0 < len(data["payerMap"]) <= 1000):
            raise ValueError()
        payers = data["payerMap"]
        for key, entry in payers.items():
            if not isinstance(key, str) or not re.fullmatch(r"[0-9]{12}", key) or not isinstance(entry, dict):
                raise ValueError()
            metric, domain = entry["amount"], entry["domainId"]
            raw, currency = metric["amount"], metric["currencyCode"]
            if (isinstance(raw, bool) or not isinstance(raw, (str, int, Decimal)) or len(str(raw)) > 128
                    or not isinstance(currency, str) or currency not in CURRENCIES
                    or not isinstance(domain, str) or not 0 < len(domain) <= 512):
                raise ValueError()
            amount = Decimal(raw)
            if not amount.is_finite() or amount.copy_abs() > Decimal("1e30") or amount.as_tuple().exponent < -64:
                raise ValueError()
    except (KeyError, TypeError, ValueError, InvalidOperation):
        raise AwsFailure(UNAVAILABLE) from None
    if payer_id is not None and payer_id not in payers:
        raise ValueError("付款账号不在当前 AWS Bills 返回的可选范围内")
    selected = payer_id or next(iter(payers))
    entry = payers[selected]
    return {
        "amount": format(Decimal(entry["amount"]["amount"]), "f"), "currency": entry["amount"]["currencyCode"],
        "period_start": start, "period_end": end, "estimated": True, "source": "aws_bills_console",
        "billing_kind": "proforma" if entry["domainId"].startswith("proforma_") else "billable",
        "payer_id": selected, "available_payers": list(payers),
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def _allowed(url, route, method):
    try:
        if not isinstance(url, str) or len(url) > 32768 or "\\" in url or any(ord(c) < 32 for c in url):
            return False
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
            return False
        pair = parsed.hostname, parsed.path
        if parsed.fragment and not (route == "login" and pair == ("us-east-1.console.aws.amazon.com", "/billing/home")
                                    and parsed.fragment in {"/bills", "/bills/", "bills"}):
            return False
        if route == "sts":
            return method == "POST" and not parsed.query and pair in {
                ("sts.us-east-1.amazonaws.com", "/"), ("sts.amazonaws.com", "/"),
            }
        if route == "token":
            return method == "POST" and not parsed.query and pair == ("signin.aws.amazon.com", "/federation")
        if route == "bill":
            return method == "GET" and pair == ("us-east-1.console.aws.amazon.com", BILL_PATH)
        return method == "GET" and pair in {
            ("signin.aws.amazon.com", "/federation"), ("signin.aws.amazon.com", "/oauth"),
            ("us-east-1.console.aws.amazon.com", "/billing/home"),
        }
    except ValueError:
        return False


def _json(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    try:
        return json.loads(body, parse_float=Decimal, parse_int=Decimal, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise AwsFailure(UNAVAILABLE) from None


class _ConsoleHTTP:
    def __init__(self, gateway):
        self.gateway = gateway
        self.deadline, self.total = time.monotonic() + TOTAL_TIMEOUT, 0
        self.session = request_session(gateway.proxy.url if gateway.proxy else None)
        for prefix in ("http://", "https://"):
            self.session.get_adapter(prefix).close()
            self.session.mount(prefix, DeadlineAdapter(self.deadline))
        self.session.headers.update({"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip, deflate"})

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise AwsFailure("AWS Bills 查询超时，请稍后重试")
        return remaining

    def request(self, method, url, route="login", **kwargs):
        # Check the un-normalized URL too: requests may collapse dot segments.
        if not _allowed(url, route, method):
            raise AwsFailure("AWS Bills 跳转地址不受支持，请重试")
        # Only the verified Bills UI fragments pass the original URL check.
        # Fragments are client navigation state and never belong on the wire.
        url = urlunsplit(urlsplit(url)._replace(fragment=""))
        try:
            prepared = self.session.prepare_request(requests.Request(method, url, **kwargs))
        except (requests.RequestException, ValueError, UnicodeError):
            raise AwsFailure(UNAVAILABLE) from None
        return self.send(prepared, route)

    def send(self, prepared, route):
        if not _allowed(prepared.url, route, prepared.method):
            raise AwsFailure("AWS Bills 跳转地址不受支持，请重试")
        self.gateway._check_proxy()
        remaining = self.remaining()
        response = None
        try:
            # Session.send resolves a next redirect and consumes its body even
            # with allow_redirects=False. Use the adapter and cookie jar directly.
            response = self.session.get_adapter(prepared.url).send(
                prepared, stream=True, verify=True, proxies=self.session.proxies,
                timeout=Timeout(total=remaining, connect=min(5, remaining), read=min(30, remaining)),
            )
            self.remaining()
            extract_cookies_to_jar(self.session.cookies, prepared, response.raw)
            headers = response.headers
            if response.status_code in (301, 302, 303, 307, 308):
                return response.status_code, headers, b""
            return response.status_code, headers, self.read_body(response)
        except (requests.RequestException, HTTPError, OSError, zlib.error):
            raise AwsFailure("AWS Bills 连接失败或超时，请检查账号代理后重试") from None
        finally:
            if response is not None:
                response.close()

    def read_body(self, response):
        try:
            length = int(response.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_BODY_BYTES:
                raise ValueError()
        except ValueError:
            raise AwsFailure("AWS Bills 响应超过读取上限或长度异常") from None
        encoding = response.headers.get("Content-Encoding", "identity").lower()
        if encoding not in ("identity", "gzip", "deflate"):
            raise AwsFailure(UNAVAILABLE)
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS) if encoding != "identity" else None
        body, encoded = bytearray(), 0
        while True:
            remaining = self.remaining()
            connection = getattr(response.raw, "_connection", None)
            sock = getattr(connection, "sock", None)
            if sock is not None:
                sock.settimeout(min(30, remaining))
            chunk = response.raw.read1(64 * 1024, decode_content=False)
            self.remaining()
            if not chunk:
                break
            encoded += len(chunk)
            if encoded > MAX_BODY_BYTES:
                raise AwsFailure("AWS Bills 响应超过读取上限")
            decoded = decoder.decompress(chunk, MAX_BODY_BYTES - len(body) + 1) if decoder else chunk
            body.extend(decoded)
            self.total += len(decoded)
            if len(body) > MAX_BODY_BYTES or self.total > MAX_TOTAL_BYTES:
                raise AwsFailure("AWS Bills 响应超过读取上限")
        if decoder and (not decoder.eof or decoder.unused_data):
            raise AwsFailure(UNAVAILABLE)
        return bytes(body)

    def close(self):
        self.session.cookies.clear()
        self.session.close()


class _Body(io.BytesIO):
    def stream(self, amt=1024, decode_content=False):
        while chunk := self.read(amt):
            yield chunk


class _StsTransport:
    """Keep botocore signing/parsing, with Bills' body, URL and time bounds."""
    def __init__(self, http):
        self.http = http

    def send(self, request):
        prepared = requests.PreparedRequest()
        prepared.url, prepared.method, prepared.body = request.url, request.method, request.body
        prepared.headers = CaseInsensitiveDict(request.headers)
        status, headers, body = self.http.send(prepared, "sts")
        return AWSResponse(request.url, status, headers, _Body(body))

    def close(self):
        # The operation owns this session across STS and federation.
        pass


class _Xsrf(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("id") == "xsrfToken":
            self.values.append(values.get("value"))


def _federation(gateway, http):
    client = gateway._client("sts", region_name="us-east-1")
    try:
        client._endpoint.http_session.close()
        client._endpoint.http_session = _StsTransport(http)
        data = client.get_federation_token(
            Name="KiroBillsReadOnlyCheck", DurationSeconds=900,
            Policy=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": POLICY_ACTIONS,
                                                                       "Resource": "*"}]}, separators=(",", ":")),
        )
    except (ClientError, BotoCoreError, ResponseParserError, ValueError, TypeError, OverflowError):
        raise AwsFailure("AWS Bills 联合登录失败，请检查 sts:GetFederationToken 权限及 Billing IAM 访问设置") from None
    finally:
        client.close()
    try:
        account = gateway.account.aws_account_id
        arn = data["FederatedUser"]["Arn"]
        if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
                or not isinstance(arn, str) or not re.fullmatch(r"arn:aws:sts::" + account + r":federated-user/[^:]+", arn)):
            raise ValueError()
        credentials = data["Credentials"]
        session = {key: credentials[field] for key, field in
                   (("sessionId", "AccessKeyId"), ("sessionKey", "SecretAccessKey"), ("sessionToken", "SessionToken"))}
        if any(not isinstance(value, str) or not 0 < len(value) <= 16384 for value in session.values()):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise AwsFailure("AWS Bills 联合登录账号或临时凭证不匹配，请检查账号配置") from None
    status, _, body = http.request("POST", FEDERATION, "token", data={
        "Action": "getSigninToken", "Session": json.dumps(session, separators=(",", ":")),
    })
    if status != 200:
        raise AwsFailure("AWS Bills 联合登录不可用，请检查 Billing IAM 访问设置")
    token_data = _json(body)
    token = token_data.get("SigninToken") if isinstance(token_data, dict) else None
    if not isinstance(token, str) or not 0 < len(token) <= 16384:
        raise AwsFailure(UNAVAILABLE)
    return token


@_protected_transport_logs()
def monthly_cost(gateway, month=None, payer_id=None):
    start, _ = current_period(month)
    month = start[:7]
    validate_payer(payer_id)
    http = _ConsoleHTTP(gateway)
    try:
        token = _federation(gateway, http)
        url = requests.Request("GET", FEDERATION, params={"Action": "login", "Destination": DESTINATION,
                                                        "SigninToken": token}).prepare().url
        # OAuth can revisit the identical home URL with newly issued cookies.
        # The hop and time budgets bound both repeated and unique redirect loops.
        for _ in range(MAX_REDIRECTS + 1):
            status, headers, body = http.request("GET", url)
            if status not in (301, 302, 303, 307, 308):
                break
            target = headers.get("Location")
            if not isinstance(target, str) or not target:
                raise AwsFailure("AWS Bills 登录跳转异常，请重试")
            # Validate before urljoin can normalize an unsafe path.
            if "/../" in target or "/./" in target or "\\" in target:
                raise AwsFailure("AWS Bills 登录跳转异常，请重试")
            url = urljoin(url, target)
        else:
            raise AwsFailure("AWS Bills 登录跳转超过上限，请稍后重试")
        if status != 200 or urlsplit(url).path != "/billing/home":
            raise AwsFailure("AWS Bills 控制台不可用，请检查 Billing IAM 访问设置")
        parser = _Xsrf()
        try:
            parser.feed(body.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise AwsFailure(UNAVAILABLE) from None
        if (len(parser.values) != 1 or not isinstance(parser.values[0], str)
                or not re.fullmatch(r"[!-~]{1,16384}", parser.values[0])):
            raise AwsFailure("AWS Bills 控制台验证信息缺失，请检查 Billing IAM 访问权限后重试")
        year, number = map(int, month.split("-"))
        status, _, body = http.request("GET", CONSOLE + BILL_PATH, "bill",
            params={"year": year, "month": number, "groupBy": "ServiceProvider"},
            headers={"x-awsbc-xsrf-token": parser.values[0], "Content-Type": "application/json"})
        if status != 200:
            raise AwsFailure("AWS Bills 账单暂不可用，请检查 Billing IAM 访问设置与账单读取权限")
        return parse_bill(_json(body), month, payer_id)
    finally:
        http.close()
