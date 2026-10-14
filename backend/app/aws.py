"""AWS provisioning adapter.

IdentityStore uses the public SDK. Password and subscription operations use the
SigV4 protocols observed in AWS console assets on 2026-09-24. These operations
are not in the public boto3 service model; protocol provenance is in docs/aws.md.
Never log request headers, credentials or password responses.
"""

import json
from contextlib import contextmanager, nullcontext
import socket
from datetime import datetime, timezone
import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from urllib3.exceptions import NameResolutionError

from .config import settings
from .security import decrypt
from .catalog import BY_SUBSCRIPTION_TYPE, PLAN_ORDER
from .aws_transport import configure_client_proxy, request_session
from .proxies import (
    ProxyUnavailable,
    account_proxy,
    check_account_proxy,
    check_selection,
    proxy_selection,
)
from .database import SessionLocal

ALIASES = {
    kind.replace("Q_DEVELOPER_STANDALONE_", "KIRO_ENTERPRISE_"): kind
    for kind in BY_SUBSCRIPTION_TYPE
}


def aws_datetime(value):
    if value is None:
        return None
    try:
        result = (
            datetime.fromtimestamp(value, timezone.utc)
            if isinstance(value, (int, float))
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
        return (
            result.replace(tzinfo=None)
            if result.tzinfo is None
            else result.astimezone(timezone.utc).replace(tzinfo=None)
        )
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise AwsFailure("AWS 订阅时间格式无法识别", uncertain=True)


class AwsFailure(Exception):
    def __init__(self, message, uncertain=False, *, code=None, http_status=None,
                 retryable=None, proven_unsent=False):
        super().__init__(message)
        self.uncertain = uncertain
        self.code = code
        self.http_status = http_status
        self.retryable = retryable
        self.proven_unsent = proven_unsent


def failure_metadata(error, *, proven_unsent=False):
    """Preserve typed retry facts while suppressing remote/request error text."""
    from .retry_policy import classify_failure

    failure = classify_failure(error)
    status = (error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
              if isinstance(error, ClientError) else None)
    return {"code": failure.code, "http_status": status,
            "retryable": failure.transient,
            "proven_unsent": proven_unsent or failure.proven_unsent}


def control_endpoint(region, plane):
    if plane == "kiro":
        return f"management.{region}.kiro.dev"
    if region != "us-east-1":
        raise AwsFailure("该区域需要 Kiro 管理接口，请重新检测当前订阅区域的配置")
    return "codewhisperer.us-east-1.amazonaws.com"


def profile_applications(profile):
    identity = profile.get("identityDetails", {}).get("ssoIdentityDetails", {})
    client = identity.get("oidcClientId")
    if client and client.startswith("arn:aws:sso:"):
        return {client}
    return {
        x["applicationArn"]
        for x in profile.get("applicationProperties", [])
        if x.get("applicationArn")
    }


def dns_failure(exc):
    pending, seen = [exc], set()
    while pending and len(seen) < 30:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, (socket.gaierror, NameResolutionError)):
            return True
        pending.extend(
            x
            for x in (
                getattr(item, "reason", None),
                item.__cause__,
                item.__context__,
                *item.args,
            )
            if isinstance(x, BaseException)
        )
    return False


def signed_call(
    session, region, host, service, target, body, *, proxy_url=None, proxy_check=None
):
    operation = target.split(".")[-1]
    read_only = operation in {"ListProfiles", "ListApplicationClaims", "ListUserSubscriptions"}
    req = AWSRequest(
        method="POST",
        url=f"https://{host}/",
        data=json.dumps(body),
        headers={"Content-Type": "application/x-amz-json-1.0", "X-Amz-Target": target},
    )
    SigV4Auth(
        session.get_credentials().get_frozen_credentials(), service, region
    ).add_auth(req)
    if proxy_check:
        proxy_check()
    try:
        with request_session(proxy_url) as transport:
            response = transport.post(
                req.url,
                headers=dict(req.headers),
                data=req.body,
                timeout=(5, settings.aws_timeout),
                allow_redirects=False,
                verify=True,
            )
    except requests.RequestException as exc:
        dns = dns_failure(exc)
        reason = (
            "DNS 解析失败"
            if dns
            else "连接超时"
            if isinstance(exc, requests.ConnectTimeout)
            else "响应超时"
            if isinstance(exc, requests.Timeout)
            else "TLS 连接失败"
            if isinstance(exc, requests.exceptions.SSLError)
            else "连接中断"
        )
        uncertain = (
            not read_only and not dns and not isinstance(exc, requests.ConnectTimeout)
        )
        advice = "需核对远端结果" if uncertain else "请检查区域与连接后重试"
        raise AwsFailure(
            f"AWS {operation}（{region}，{host}）{reason}；{advice}",
            uncertain=uncertain,
            **(failure_metadata(exc) | {"proven_unsent": dns or isinstance(exc, requests.ConnectTimeout)}),
        ) from None
    try:
        data = response.json()
    except ValueError:
        raise AwsFailure(
            f"AWS {operation} 返回不可识别的响应（{region}，HTTP {response.status_code}）",
            uncertain=not read_only,
        )
    if not 200 <= response.status_code < 300:
        code = str(data.get("__type") or data.get("code") or "AwsError").split("#")[-1]
        # Deliberately exclude arbitrary AWS error text, which can echo request data.
        raise AwsFailure(
            f"AWS {target.split('.')[-1]}: {code}（HTTP {response.status_code}）",
            uncertain=not read_only
            and (response.status_code >= 500 or response.status_code in (408, 409, 425)),
            code=code, http_status=response.status_code,
            proven_unsent=(400 <= response.status_code < 500
                           and response.status_code not in (408, 409, 425)),
        )
    return data, response.headers.get("x-amzn-requestid", "")


def assignment_read_scope(gateway):
    factory = getattr(gateway, "claim_snapshot", None)
    return factory() if factory else nullcontext()


def make_session(access_key_id, secret_access_key):
    return boto3.Session(
        aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key
    )


class AwsGateway:
    def __init__(self, account):
        self.account = account
        self._clients = []
        try:
            self.proxy = (
                account._proxy_selection
                if hasattr(account, "_proxy_selection")
                else account_proxy(account)
            )
            self._check_proxy()
        except ProxyUnavailable as exc:
            raise AwsFailure(str(exc)) from None
        self.session = make_session(**decrypt(account.credentials_encrypted))
        self._identity = None

    @property
    def identity(self):
        # Native login/OIDC steps usually never use Identity Store. Loading its
        # botocore model on every durable step wastes CPU on small instances.
        if self._identity is None:
            self._identity = self._client("identitystore", region_name=self.account.region)
        return self._identity

    @identity.setter
    def identity(self, value):
        self._identity = value

    def _check_proxy(self):
        try:
            check_account_proxy(self.account, self.proxy)
        except ProxyUnavailable as exc:
            raise AwsFailure(str(exc)) from None

    def _client(self, service, **kwargs):
        client = self.session.client(
            service,
            config=Config(
                connect_timeout=5,
                read_timeout=settings.aws_timeout,
                retries={"max_attempts": 0},
                proxies={},
            ),
            **kwargs,
        )
        client = configure_client_proxy(
            client, self.proxy.url if self.proxy else None, self._check_proxy
        )
        transport = getattr(getattr(client, "_endpoint", None), "http_session", None)
        if transport is not None:
            transport.before_send = self._before_sdk_send
        self._clients.append(client)
        return client

    def _before_sdk_send(self, request):
        # Run after the transport's proxy guard. Read-only recovery must not
        # inherit the fresh-write authority check, even after permissions stop.
        target = request.headers.get("X-Amz-Target", "")
        if isinstance(target, bytes):
            target = target.decode("ascii", errors="ignore")
        guard = getattr(self, "before_provisioning_write", None)
        if guard and target.rsplit(".", 1)[-1] in {"CreateUser", "CreateGroupMembership"}:
            guard()
        cascade_guard = getattr(self, "before_cascade_wire", None)
        if cascade_guard:
            cascade_guard()

    def close(self):
        clients, self._clients = getattr(self, "_clients", []), []
        for client in clients:
            client.close()

    def _call(self, region, host, service, target, body):
        def before_wire():
            self._check_proxy()
            guard = getattr(self, "before_provisioning_write", None)
            if guard and target.split(".")[-1] in {"UpdatePassword", "CreateAssignment"}:
                guard()
            cascade_guard = getattr(self, "before_cascade_wire", None)
            if cascade_guard:
                cascade_guard()

        return signed_call(
            self.session,
            region,
            host,
            service,
            target,
            body,
            proxy_url=self.proxy.url if self.proxy else None,
            proxy_check=before_wire,
        )

    def profiles(self):
        a = self.account
        host = control_endpoint(a.subscription_region, a.control_plane)
        target = (
            "KiroControlPlaneService.ListProfiles"
            if a.control_plane == "kiro"
            else "AWSCodeWhispererService.ListProfiles"
        )
        data, _ = self._call(a.subscription_region, host, "codewhisperer", target, {})
        return data.get("profiles", [])

    def verify(self):
        a = self.account
        if a.profile_arn.split(":")[3] != a.subscription_region:
            raise AwsFailure(
                "Kiro 配置所在区域与订阅区域不一致，请重新检测并选择当前区域的配置；身份中心区域可以不同"
            )
        if not any(
            p.get("arn") == a.profile_arn
            and p.get("identityDetails", {})
            .get("ssoIdentityDetails", {})
            .get("instanceArn")
            == a.instance_arn
            and a.application_arn in profile_applications(p)
            and p.get("identityDetails", {})
            .get("ssoIdentityDetails", {})
            .get("ssoRegion", a.region)
            == a.region
            for p in self.profiles()
        ):
            raise AwsFailure(
                "所选 Kiro 配置与 IAM Identity Center 实例或应用不匹配，请重新检测配置"
            )
        account_id = self.verify_identity()
        # Read subscription claims as a preflight, so reconciliation is available.
        self._claims()
        return account_id

    def verify_identity(self):
        """Creating an SSO user does not depend on Kiro subscription services."""
        try:
            identity = self._client(
                "sts", region_name=self.account.region
            ).get_caller_identity()
            self.identity.list_users(
                IdentityStoreId=self.account.identity_store_id, MaxResults=1
            )
        except ClientError as exc:
            raise AwsFailure(
                f"AWS 身份中心验证失败：{exc.response.get('Error', {}).get('Code', 'ClientError')}",
                **failure_metadata(exc, proven_unsent=True),
            ) from None
        except BotoCoreError as exc:
            raise AwsFailure(
                f"AWS 身份中心连接失败（{self.account.region}，{type(exc).__name__}），请检查区域与连接",
                **failure_metadata(exc, proven_unsent=True),
            ) from None
        return identity["Account"]

    def find_created_user(self, record):
        """Read-only recovery of the user belonging to this exact request."""
        marker = f"Kiro Console {record.id}"
        try:
            # Reconcile only users created by this exact durable request.
            result = self.identity.get_user_id(
                IdentityStoreId=self.account.identity_store_id,
                AlternateIdentifier={
                    "UniqueAttribute": {
                        "AttributePath": "userName",
                        "AttributeValue": record.username,
                    }
                },
            )
            user = self.identity.describe_user(
                IdentityStoreId=self.account.identity_store_id, UserId=result["UserId"]
            )
            if user.get("DisplayName") != marker:
                raise AwsFailure("AWS 用户名已被其他账号使用，请重新创建")
            return result["UserId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return None

    def create_user(self, record):
        try:
            user_id = self.find_created_user(record)
        except (ClientError, BotoCoreError) as exc:
            # This read failed before any CreateUser dispatch. The caller can
            # safely release its conservative pre-call intent and retry later.
            raise AwsFailure(f"AWS 用户核对失败（{type(exc).__name__}），尚未发送创建",
                             **failure_metadata(exc, proven_unsent=True)) from None
        if user_id:
            return user_id
        # The lookup above may block while local authority/configuration changes.
        # Keep create_user(record) compatible with existing gateway factories.
        before_create = getattr(self, "before_create_user", None)
        if before_create:
            before_create()
        response = self.identity.create_user(
            IdentityStoreId=self.account.identity_store_id,
            UserName=record.username,
            DisplayName=f"Kiro Console {record.id}",
            Name={"GivenName": record.username, "FamilyName": "Kiro"},
            Emails=[{"Value": record.email, "Primary": True, "Type": "work"}],
        )
        return response["UserId"]

    def list_groups(self):
        groups, token = [], None
        while True:
            args = {"IdentityStoreId": self.account.identity_store_id}
            if token:
                args["NextToken"] = token
            response = self.identity.list_groups(**args)
            groups.extend(self._group_view(g) for g in response.get("Groups", []))
            token = response.get("NextToken")
            if not token:
                return groups

    @staticmethod
    def _group_view(group):
        return {
            "id": group["GroupId"],
            "name": group.get("DisplayName", ""),
            "description": group.get("Description", ""),
        }

    def get_group_id(self, name):
        try:
            return self.identity.get_group_id(
                IdentityStoreId=self.account.identity_store_id,
                AlternateIdentifier={
                    "UniqueAttribute": {
                        "AttributePath": "displayName",
                        "AttributeValue": name,
                    }
                },
            )["GroupId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    def get_group(self, group_id):
        try:
            return self._group_view(
                self.identity.describe_group(
                    IdentityStoreId=self.account.identity_store_id, GroupId=group_id
                )
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    def create_group(self, name, marker):
        return self.identity.create_group(
            IdentityStoreId=self.account.identity_store_id,
            DisplayName=name,
            Description=marker,
        )["GroupId"]

    def update_group(self, group_id, name):
        return self.identity.update_group(
            IdentityStoreId=self.account.identity_store_id,
            GroupId=group_id,
            Operations=[{"AttributePath": "displayName", "AttributeValue": name}],
        )

    def delete_group(self, group_id):
        try:
            return self.identity.delete_group(
                IdentityStoreId=self.account.identity_store_id, GroupId=group_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    def list_group_memberships(self, group_id):
        members, token, seen = [], None, set()
        for _ in range(1000):
            args = {
                "IdentityStoreId": self.account.identity_store_id,
                "GroupId": group_id,
            }
            if token:
                args["NextToken"] = token
            response = self.identity.list_group_memberships(**args)
            if not isinstance(response, dict) or not isinstance(response.get("GroupMemberships"), list):
                raise AwsFailure("AWS 分组成员响应不完整，无法安全操作", uncertain=True)
            for member in response["GroupMemberships"]:
                if (not isinstance(member, dict) or not isinstance(member.get("MembershipId"), str)
                        or not member["MembershipId"] or not isinstance(member.get("MemberId"), dict)
                        or not isinstance(member["MemberId"].get("UserId"), str) or not member["MemberId"]["UserId"]
                        or member.get("IdentityStoreId") != self.account.identity_store_id
                        or "GroupId" in member and member["GroupId"] != group_id):
                    raise AwsFailure("AWS 分组成员响应不完整，无法安全操作", uncertain=True)
                members.append({"id": member["MembershipId"], "user_id": member["MemberId"]["UserId"]})
            if "NextToken" not in response:
                return members
            token = response["NextToken"]
            if not isinstance(token, str) or not token:
                raise AwsFailure("AWS 分组成员分页响应异常，无法安全操作", uncertain=True)
            if token in seen:
                break
            seen.add(token)
        raise AwsFailure("AWS 分组成员分页未完整返回，无法安全操作", uncertain=True)

    def get_group_membership(self, group_id, user_id):
        try:
            return self.identity.get_group_membership_id(
                IdentityStoreId=self.account.identity_store_id,
                GroupId=group_id,
                MemberId={"UserId": user_id},
            )["MembershipId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    def create_group_membership(self, group_id, user_id):
        guard = getattr(self, "before_provisioning_write", None)
        if guard:
            guard()
        return self.identity.create_group_membership(
            IdentityStoreId=self.account.identity_store_id,
            GroupId=group_id,
            MemberId={"UserId": user_id},
        )["MembershipId"]

    def delete_group_membership(self, membership_id):
        try:
            return self.identity.delete_group_membership(
                IdentityStoreId=self.account.identity_store_id,
                MembershipId=membership_id,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    def password(self, record):
        region = self.account.region
        dashed = {
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "ap-south-1",
            "eu-north-1",
            "eu-west-3",
            "sa-east-1",
            "us-west-1",
        }
        host = (
            f"up-sso.{region}.amazonaws.com"
            if region in dashed
            else f"up.sso.{region}.amazonaws.com"
        )
        data, _ = self._call(
            region,
            host,
            "userpool",
            "SWBUPService.UpdatePassword",
            {
                "IdentityStoreId": self.account.identity_store_id,
                "UserId": record.sso_user_id,
                "PasswordMode": "OTP",
            },
        )
        if not isinstance(data.get("Password"), str) or not data["Password"]:
            raise AwsFailure("AWS 未返回一次性密码；结果不明，请显式重置后恢复", uncertain=True)
        return data["Password"]

    def subscribe(self, record):
        a = self.account
        host = control_endpoint(a.subscription_region, a.control_plane)
        prefix = (
            "KiroControlPlaneQDeveloperService"
            if a.control_plane == "kiro"
            else "AmazonQDeveloperService"
        )
        _, request_id = self._call(
            a.subscription_region,
            host,
            "q",
            prefix + ".CreateAssignment",
            {
                "principalId": record.sso_user_id,
                "principalType": "USER",
                "subscriptionType": record.subscription_type,
            },
        )
        return request_id

    def subscribe_group(self, group, subscription_type):
        if subscription_type not in BY_SUBSCRIPTION_TYPE:
            raise AwsFailure("目标套餐不受支持")
        return self._group_assignment("CreateAssignment", group, {
            "subscriptionType": subscription_type,
        })

    def cancel_group_subscription(self, group, mode):
        if mode not in ("IMMEDIATE", "END_OF_PERIOD"):
            raise AwsFailure("不支持的取消方式")
        if self.account.control_plane != "kiro" and mode != "IMMEDIATE":
            raise AwsFailure("该 AWS 账号的旧控制面仅支持立即移除访问")
        return self._group_assignment("DeleteAssignment", group, {
            "deletionMode": mode,
        } if self.account.control_plane == "kiro" else {})

    def _group_assignment(self, action, group, body):
        a = self.account
        prefix = "KiroControlPlaneQDeveloperService" if a.control_plane == "kiro" else "AmazonQDeveloperService"
        _, request_id = self._call(
            a.subscription_region, control_endpoint(a.subscription_region, a.control_plane),
            "q", prefix + "." + action,
            {"principalId": group.remote_id, "principalType": "GROUP", **body},
        )
        return request_id

    @contextmanager
    def claim_snapshot(self):
        # A snapshot lives only for one read phase; callers end it before any
        # assignment write and open a fresh snapshot for readback.
        previous = getattr(self, "_claim_snapshot", None)
        self._claim_snapshot = None
        try:
            self._claim_snapshot = self.all_assignment_claims()
            yield
        finally:
            self._claim_snapshot = previous

    def all_assignment_claims(self):
        if getattr(self, "_claim_snapshot", None) is not None:
            return self._claim_snapshot
        token, seen, claims = None, set(), []
        for _ in range(1000):
            data = self._claims(token)
            for claim in data["claims"]:
                principal = claim.get("principal") if isinstance(claim, dict) else None
                if (not isinstance(principal, dict) or len(principal) != 1
                    or not (set(principal) <= {"user", "group"})
                    or not all(isinstance(v, str) and v for v in principal.values())):
                    raise AwsFailure("AWS 订阅主体格式不明确，请核对", uncertain=True)
                claims.append(claim)
            token = data.get("nextToken")
            if not token:
                return claims
            if token in seen:
                break
            seen.add(token)
        raise AwsFailure("AWS 订阅分页未完整返回，无法安全操作", uncertain=True)

    @staticmethod
    def assignment_claim_info(claim, *, allow_pending=True):
        raw_type, raw_pending = claim.get("type"), claim.get("newType")
        if not isinstance(raw_type, dict) or (raw_pending is not None and not isinstance(raw_pending, dict)):
            raise AwsFailure("AWS 订阅类型格式不明确，请核对", uncertain=True)
        kind, pending = raw_type.get("amazonQ"), (raw_pending or {}).get("amazonQ")
        kind, pending = ALIASES.get(kind, kind), ALIASES.get(pending, pending)
        if kind not in PLAN_ORDER or (pending is not None and (
            pending not in PLAN_ORDER or PLAN_ORDER[pending] >= PLAN_ORDER[kind]
        )):
            raise AwsFailure("AWS 订阅类型未知或待生效变更不明确，请核对", uncertain=True)
        boundary = aws_datetime(claim.get("expirationDate"))
        expires = None if pending else boundary
        return {"status": "cancelled" if expires else "active",
                "subscription_type": kind, "expires_at": expires,
                "pending_type": pending, "expected_effective_at": boundary if pending else None}

    def group_subscription_info(self, group):
        matches = [self.assignment_claim_info(c) for c in self.all_assignment_claims()
                   if c.get("principal", {}).get("group") == group.remote_id]
        if len(matches) > 1:
            raise AwsFailure("AWS 分组存在多个订阅声明，请核对", uncertain=True)
        return matches[0] if matches else {
            "status": "not_subscribed", "subscription_type": None, "expires_at": None,
        }

    def list_user_memberships(self, user_id):
        token, seen, memberships = None, set(), {}
        for _ in range(1000):
            body = {"IdentityStoreId": self.account.identity_store_id,
                    "MemberId": {"UserId": user_id}, "MaxResults": 100}
            if token:
                body["NextToken"] = token
            data = self.identity.list_group_memberships_for_member(**body)
            rows = data.get("GroupMemberships")
            if not isinstance(rows, list):
                raise AwsFailure("AWS 用户分组查询格式不明确，请核对", uncertain=True)
            for row in rows:
                gid, mid = row.get("GroupId"), row.get("MembershipId")
                if not gid or not mid or gid in memberships:
                    raise AwsFailure("AWS 用户分组声明重复或格式不明确", uncertain=True)
                memberships[gid] = mid
            token = data.get("NextToken")
            if not token:
                return memberships
            if token in seen:
                break
            seen.add(token)
        raise AwsFailure("AWS 用户分组分页未完整返回，无法安全操作", uncertain=True)

    def user_subscription_sources(self, record):
        """Resolve all inherited claims with one paginated lookup per user."""
        claims = self.all_assignment_claims()
        memberships = self.list_user_memberships(record.sso_user_id) if any(
            c.get("principal", {}).get("group") for c in claims
        ) else {}
        result = []
        for claim in claims:
            principal = claim.get("principal", {})
            if principal.get("user") == record.sso_user_id:
                result.append({"source": "USER", "group_id": None,
                               **self.assignment_claim_info(claim, allow_pending=True)})
            elif principal.get("group") in memberships:
                result.append({"source": "GROUP", "group_id": principal["group"],
                               **self.assignment_claim_info(claim)})
        return result

    def update_assignment(self, record, target_type):
        """AWS console UpdateAssignment (2026-10-10); never retry a write blindly."""
        if target_type not in BY_SUBSCRIPTION_TYPE:
            raise AwsFailure("目标套餐不受支持")
        a = self.account
        prefix = (
            "KiroControlPlaneQDeveloperService"
            if a.control_plane == "kiro"
            else "AmazonQDeveloperService"
        )
        _, request_id = self._call(
            a.subscription_region,
            control_endpoint(a.subscription_region, a.control_plane),
            "q",
            prefix + ".UpdateAssignment",
            {
                "principalId": record.sso_user_id,
                "principalType": "USER",
                "subscriptionType": target_type,
            },
        )
        return request_id

    def plan_change_info(self, record):
        """Only the exact USER claim can determine a USER plan change."""
        info = self.subscription_info(record)
        return {"status": info["status"], "current_type": info["subscription_type"],
                "pending_type": info.get("pending_type"),
                "expected_effective_at": info.get("expected_effective_at")}

    def cancel_subscription(self, record, mode):
        a = self.account
        body = {"principalId": record.sso_user_id, "principalType": "USER"}
        if a.control_plane == "kiro":
            body["deletionMode"] = mode
            host = control_endpoint(a.subscription_region, a.control_plane)
            target = "KiroControlPlaneQDeveloperService.DeleteAssignment"
        else:
            if mode != "IMMEDIATE":
                raise AwsFailure("该 AWS 账号的旧控制面仅支持立即移除访问")
            host = control_endpoint(a.subscription_region, a.control_plane)
            target = "AmazonQDeveloperService.DeleteAssignment"
        _, request_id = self._call(a.subscription_region, host, "q", target, body)
        return request_id

    def user_info(self, record):
        try:
            return self.identity.describe_user(
                IdentityStoreId=self.account.identity_store_id,
                UserId=record.sso_user_id,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return None
            raise

    def delete_user(self, record):
        try:
            response = self.identity.delete_user(
                IdentityStoreId=self.account.identity_store_id,
                UserId=record.sso_user_id,
            )
            return response.get("ResponseMetadata", {}).get("RequestId")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return None
            raise

    def update_user(self, record, display_name, email):
        response = self.identity.update_user(
            IdentityStoreId=self.account.identity_store_id,
            UserId=record.sso_user_id,
            Operations=[
                {"AttributePath": "displayName", "AttributeValue": display_name},
                {
                    "AttributePath": "emails",
                    "AttributeValue": [
                        {"Value": email, "Primary": True, "Type": "work"}
                    ],
                },
            ],
        )
        return response.get("ResponseMetadata", {}).get("RequestId")

    def subscription_info(self, record):
        """Observe the exact USER assignment; effective access is a separate query."""
        matches = [self.assignment_claim_info(c) for c in self.all_assignment_claims()
                   if c.get("principal", {}).get("user") == record.sso_user_id]
        if len(matches) > 1:
            raise AwsFailure("AWS 存在多个 USER 订阅声明，请核对", uncertain=True)
        return matches[0] if matches else {
            "status": "not_subscribed", "subscription_type": None, "expires_at": None,
            "pending_type": None, "expected_effective_at": None,
        }

    def _claims(self, token=None):
        a = self.account
        body = {
            "applicationArn": a.application_arn,
            "subscriptionRegion": a.subscription_region,
            "maxResults": 100,
        }
        if token:
            body["nextToken"] = token
        data, _ = self._call(
            a.region,
            f"service.user-subscriptions.{a.region}.amazonaws.com",
            "user-subscriptions",
            "AWSZornControlPlaneService.ListApplicationClaims",
            body,
        )
        if not isinstance(data, dict) or not isinstance(data.get("claims"), list):
            raise AwsFailure("AWS 订阅查询格式已变更，无法核对开通结果", uncertain=True)
        return data

    def report_subscriptions(self):
        from .aws_report_gateway import subscriptions
        return subscriptions(self)

    def report_claims(self):
        from .aws_report_gateway import pages
        return pages(self._claims, "claims", "nextToken")

    def report_users(self):
        from .aws_report_gateway import directory
        return directory(self, "Users")

    def report_groups(self):
        from .aws_report_gateway import directory
        return directory(self, "Groups")

    def monthly_cost(self, month=None, payer_id=None):
        from .aws_bills import monthly_cost
        return monthly_cost(self, month, payer_id)

    def is_subscribed(self, record):
        aliases = {
            "Q_DEVELOPER_STANDALONE_PRO": "KIRO_ENTERPRISE_PRO",
            "Q_DEVELOPER_STANDALONE_PRO_PLUS": "KIRO_ENTERPRISE_PRO_PLUS",
            "Q_DEVELOPER_STANDALONE_POWER": "KIRO_ENTERPRISE_POWER",
            "Q_DEVELOPER_STANDALONE_PRO_MAX": "KIRO_ENTERPRISE_PRO_MAX",
        }
        token = None
        seen = set()
        while True:
            data = self._claims(token)
            for claim in data["claims"]:
                if claim.get("principal", {}).get("user") != record.sso_user_id:
                    continue
                kind = claim.get("type", {}).get("amazonQ")
                if kind in (
                    record.subscription_type,
                    aliases.get(record.subscription_type),
                ) and not claim.get("expirationDate"):
                    return True
            token = data.get("nextToken")
            if not token:
                return False
            if token in seen:
                raise AwsFailure("AWS 订阅查询分页异常", uncertain=True)
            seen.add(token)


def discover(body, *, selection=None):
    if selection is None and getattr(body, "proxy_id", None) is not None:
        try:
            with SessionLocal() as db:
                selection = proxy_selection(db, body.proxy_id)
        except ProxyUnavailable as exc:
            raise AwsFailure(str(exc)) from None

    def guard():
        try:
            with SessionLocal() as db:
                check_selection(db, selection)
        except ProxyUnavailable as exc:
            raise AwsFailure(str(exc)) from None

    guard()
    session = make_session(body.access_key_id, body.secret_access_key)
    config = Config(
        connect_timeout=5,
        read_timeout=settings.aws_timeout,
        retries={"max_attempts": 0},
        proxies={},
    )
    proxy_url = selection.url if selection else None
    sts = configure_client_proxy(
        session.client("sts", region_name=body.region, config=config), proxy_url, guard
    )
    account_id = sts.get_caller_identity()["Account"]
    sso = configure_client_proxy(
        session.client("sso-admin", region_name=body.region, config=config),
        proxy_url,
        guard,
    )
    instances = sso.list_instances()["Instances"]
    profiles, warnings = [], []
    planes = [("kiro", "KiroControlPlaneService")]
    if body.subscription_region == "us-east-1":
        planes.append(("legacy", "AWSCodeWhispererService"))
    successful_queries = 0
    for plane, target in planes:
        try:
            data, _ = signed_call(
                session,
                body.subscription_region,
                control_endpoint(body.subscription_region, plane),
                "codewhisperer",
                target + ".ListProfiles",
                {},
                proxy_url=proxy_url,
                proxy_check=guard,
            )
            successful_queries += 1
        except AwsFailure as exc:
            warnings.append(str(exc))
            continue
        for p in data.get("profiles", []):
            identity = p.get("identityDetails", {}).get("ssoIdentityDetails", {})
            instance = next(
                (
                    i
                    for i in instances
                    if i["InstanceArn"] == identity.get("instanceArn")
                ),
                None,
            )
            if not instance:
                continue
            apps = sso.list_applications(InstanceArn=instance["InstanceArn"]).get(
                "Applications", []
            )
            expected = profile_applications(p)
            matching = [
                a
                for a in apps
                if a["ApplicationArn"] in expected and a.get("Status") == "ENABLED"
            ]
            for a in matching:
                if any(
                    x["profile_arn"] == p["arn"]
                    and x["application_arn"] == a["ApplicationArn"]
                    for x in profiles
                ):
                    continue
                profiles.append(
                    {
                        "profile_arn": p["arn"],
                        "profile_name": p["profileName"],
                        "control_plane": plane,
                        "instance_arn": instance["InstanceArn"],
                        "identity_store_id": instance["IdentityStoreId"],
                        "application_arn": a["ApplicationArn"],
                        "portal_url": p.get("startUrl")
                        or f"https://{instance['IdentityStoreId']}.awsapps.com/start",
                        "region": body.region,
                        "subscription_region": body.subscription_region,
                    }
                )
    if not successful_queries:
        raise AwsFailure("；".join(warnings))
    return {
        "aws_account_id": account_id,
        "profiles": profiles,
        "warnings": warnings,
        "message": None
        if profiles
        else f"{body.subscription_region} 未发现与此身份中心关联的 Kiro 配置；请先在 AWS 控制台切换到该订阅区域并完成企业配置。",
    }
