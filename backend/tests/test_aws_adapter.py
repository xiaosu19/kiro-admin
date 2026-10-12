import json
from types import SimpleNamespace

import boto3
import pytest
import requests
from botocore.stub import Stubber

from app import aws
from app.database import SessionLocal
from app.models import AwsAccount


def patch_post(monkeypatch, call):
    monkeypatch.setattr(
        aws.requests.Session, "post", lambda self, *a, **kw: call(*a, **kw)
    )


def gateway():
    with SessionLocal() as db:
        return aws.AwsGateway(db.get(AwsAccount, 1))


def test_signed_password_protocol_and_no_redirect(monkeypatch):
    def post(url, **kw):
        assert url == "https://up.sso.us-east-1.amazonaws.com/"
        assert kw["headers"]["X-Amz-Target"] == "SWBUPService.UpdatePassword"
        assert "/us-east-1/userpool/aws4_request" in kw["headers"]["Authorization"]
        assert json.loads(kw["data"]) == {
            "IdentityStoreId": "d-1234567890",
            "UserId": "user-1",
            "PasswordMode": "OTP",
        }
        assert kw["allow_redirects"] is False
        return SimpleNamespace(
            status_code=200, headers={}, json=lambda: {"Password": "one-time"}
        )

    patch_post(monkeypatch, post)
    assert gateway().password(SimpleNamespace(sso_user_id="user-1")) == "one-time"


@pytest.mark.parametrize("tier", ["PRO", "PRO_PLUS", "PRO_MAX", "POWER"])
@pytest.mark.parametrize(
    "plane,host,target",
    [
        (
            "legacy",
            "codewhisperer.us-east-1.amazonaws.com",
            "AmazonQDeveloperService.CreateAssignment",
        ),
        (
            "kiro",
            "management.us-east-1.kiro.dev",
            "KiroControlPlaneQDeveloperService.CreateAssignment",
        ),
    ],
)
def test_subscription_protocol_uses_correct_sigv4_service(
    plane, host, target, monkeypatch, tier
):
    def post(url, **kw):
        assert url == f"https://{host}/"
        assert kw["headers"]["X-Amz-Target"] == target
        assert "/us-east-1/q/aws4_request" in kw["headers"]["Authorization"]
        body = json.loads(kw["data"])
        assert body == {
            "principalId": "user-1",
            "principalType": "USER",
            "subscriptionType": f"Q_DEVELOPER_STANDALONE_{tier}",
        }
        return SimpleNamespace(
            status_code=200, headers={"x-amzn-requestid": "request-1"}, json=lambda: {}
        )

    patch_post(monkeypatch, post)
    g = gateway()
    g.account.control_plane = plane
    assert (
        g.subscribe(
            SimpleNamespace(
                sso_user_id="user-1", subscription_type=f"Q_DEVELOPER_STANDALONE_{tier}"
            )
        )
        == "request-1"
    )


@pytest.mark.parametrize("tier", ["POWER", "PRO_MAX"])
def test_claim_reconciliation_matches_user_and_tier_across_pages(monkeypatch, tier):
    g = gateway()
    pages = [
        {
            "claims": [
                {
                    "principal": {"user": "other"},
                    "type": {"amazonQ": f"KIRO_ENTERPRISE_{tier}"},
                }
            ],
            "nextToken": "next",
        },
        {
            "claims": [
                {
                    "principal": {"user": "user-1"},
                    "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"},
                },
                {
                    "principal": {"user": "user-1"},
                    "type": {"amazonQ": f"KIRO_ENTERPRISE_{tier}"},
                },
            ]
        },
    ]
    monkeypatch.setattr(g, "_claims", lambda token: pages.pop(0))
    assert g.is_subscribed(
        SimpleNamespace(
            sso_user_id="user-1", subscription_type=f"Q_DEVELOPER_STANDALONE_{tier}"
        )
    )
    assert not pages


@pytest.mark.parametrize(
    "status,uncertain", [(403, False), (429, False), (409, True), (425, True), (500, True)]
)
def test_aws_errors_classify_write_uncertainty_and_hide_echoed_secrets(
    status, uncertain, monkeypatch
):
    patch_post(
        monkeypatch,
        lambda *a, **kw: SimpleNamespace(
            status_code=status,
            headers={},
            json=lambda: {
                "__type": "AWS#AccessDenied",
                "message": "secret echoed here",
            },
        ),
    )
    session = boto3.Session(aws_access_key_id="TEST", aws_secret_access_key="TEST")
    with pytest.raises(aws.AwsFailure) as error:
        aws.signed_call(
            session,
            "us-east-1",
            "example.amazonaws.com",
            "q",
            "Service.CreateAssignment",
            {},
        )
    assert error.value.uncertain == uncertain
    assert "secret" not in str(error.value)


def test_aws_timeout_never_implies_subscription_failure(monkeypatch):
    def timeout(*a, **kw):
        raise requests.Timeout()

    patch_post(monkeypatch, timeout)
    session = boto3.Session(aws_access_key_id="TEST", aws_secret_access_key="TEST")
    with pytest.raises(aws.AwsFailure) as error:
        aws.signed_call(
            session,
            "us-east-1",
            "example.amazonaws.com",
            "q",
            "Service.CreateAssignment",
            {},
        )
    assert error.value.uncertain


def test_readonly_connection_failure_has_actionable_context_not_write_uncertainty(
    monkeypatch,
):
    def timeout(*a, **kw):
        raise requests.ReadTimeout("this may contain secret request data")

    patch_post(monkeypatch, timeout)
    g = gateway()
    g.account.subscription_region = "eu-central-1"
    g.account.control_plane = "kiro"
    with pytest.raises(aws.AwsFailure) as error:
        g.profiles()
    assert not error.value.uncertain
    message = str(error.value)
    assert (
        "ListProfiles" in message
        and "eu-central-1" in message
        and "响应超时" in message
    )
    assert "核对远端" not in message and "secret" not in message


def test_dns_failure_is_distinct_from_an_unknown_write(monkeypatch):
    import socket
    from urllib3.exceptions import MaxRetryError, NameResolutionError

    nested = MaxRetryError(
        None,
        "/",
        NameResolutionError(
            "example.amazonaws.com", None, socket.gaierror(-2, "not found")
        ),
    )

    def dns(*a, **kw):
        raise requests.ConnectionError(nested)

    patch_post(monkeypatch, dns)
    with pytest.raises(aws.AwsFailure) as error:
        gateway().subscribe(
            SimpleNamespace(
                sso_user_id="test", subscription_type="Q_DEVELOPER_STANDALONE_PRO"
            )
        )
    assert not error.value.uncertain and "DNS 解析失败" in str(error.value)


def test_frankfurt_uses_kiro_endpoint_and_rejects_legacy(monkeypatch):
    seen = []

    def call(session, region, host, service, target, body, **kw):
        seen.append((region, host, target))
        return {}, "request"

    monkeypatch.setattr(aws, "signed_call", call)
    g = gateway()
    g.account.subscription_region = "eu-central-1"
    g.account.control_plane = "kiro"
    r = SimpleNamespace(sso_user_id="u", subscription_type="Q_DEVELOPER_STANDALONE_PRO")
    g.profiles()
    g.subscribe(r)
    g.cancel_subscription(r, "IMMEDIATE")
    assert len(seen) == 3 and all(
        x[0] == "eu-central-1" and x[1] == "management.eu-central-1.kiro.dev"
        for x in seen
    )
    g.account.control_plane = "legacy"
    with pytest.raises(aws.AwsFailure):
        g.profiles()
    assert len(seen) == 3


def test_discovery_matches_profile_application_across_identity_regions(monkeypatch):
    instance = "arn:aws:sso:::instance/ssoins-test"
    app = "arn:aws:sso::123456789012:application/ssoins-test/apl-europe"
    profile = {
        "arn": "arn:aws:codewhisperer:eu-central-1:123456789012:profile/EU",
        "profileName": "Kiro EU",
        "identityDetails": {
            "ssoIdentityDetails": {
                "instanceArn": instance,
                "ssoRegion": "us-east-1",
                "oidcClientId": app,
            }
        },
    }

    class FakeSso:
        def list_instances(self):
            return {
                "Instances": [
                    {"InstanceArn": instance, "IdentityStoreId": "d-1234567890"}
                ]
            }

        def list_applications(self, **kw):
            return {
                "Applications": [
                    {"ApplicationArn": app, "Name": "Kiro EU", "Status": "ENABLED"},
                    {
                        "ApplicationArn": app + "-signin",
                        "Name": "Kiro Sign-In - EU",
                        "Status": "ENABLED",
                    },
                    {
                        "ApplicationArn": app + "-us",
                        "Name": "Kiro US",
                        "Status": "DISABLED",
                    },
                ]
            }

    class FakeSession:
        def client(self, service, **kw):
            if service == "sts":
                return SimpleNamespace(
                    get_caller_identity=lambda: {"Account": "123456789012"}
                )
            assert service == "sso-admin" and kw["region_name"] == "us-east-1"
            return FakeSso()

    monkeypatch.setattr(aws, "make_session", lambda *a: FakeSession())
    monkeypatch.setattr(aws, "configure_client_proxy", lambda client, *a: client)

    def call(session, region, host, service, target, body, **kw):
        assert host == "management.eu-central-1.kiro.dev"
        return {"profiles": [profile]}, ""

    monkeypatch.setattr(aws, "signed_call", call)
    result = aws.discover(
        SimpleNamespace(
            access_key_id="test",
            secret_access_key="test",
            region="us-east-1",
            subscription_region="eu-central-1",
        )
    )
    assert len(result["profiles"]) == 1
    assert result["profiles"][0]["application_arn"] == app
    assert result["profiles"][0]["region"] == "us-east-1"
    assert result["profiles"][0]["subscription_region"] == "eu-central-1"


def test_verify_rejects_wrong_profile_region_or_application_before_other_calls(
    monkeypatch,
):
    g = gateway()
    g.account.subscription_region = "eu-central-1"
    with pytest.raises(aws.AwsFailure, match="区域不一致"):
        g.verify()
    g.account.subscription_region = "us-east-1"
    profile = {
        "arn": g.account.profile_arn,
        "identityDetails": {
            "ssoIdentityDetails": {
                "instanceArn": g.account.instance_arn,
                "oidcClientId": g.account.application_arn + "-wrong",
            }
        },
    }
    monkeypatch.setattr(g, "profiles", lambda: [profile])
    with pytest.raises(aws.AwsFailure, match="应用不匹配"):
        g.verify()


@pytest.mark.parametrize("new_unavailable", [False, True])
def test_us_discovery_deduplicates_or_falls_back_to_working_read_endpoint(
    monkeypatch, new_unavailable
):
    application = "arn:aws:sso::123456789012:application/ssoins-test/apl-test"
    instance = "arn:aws:sso:::instance/ssoins-test"
    profile = {
        "arn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/US",
        "profileName": "Kiro US",
        "identityDetails": {
            "ssoIdentityDetails": {"instanceArn": instance, "oidcClientId": application}
        },
    }

    class Fake:
        def client(self, name, **kw):
            return self

        def get_caller_identity(self):
            return {"Account": "123456789012"}

        def list_instances(self):
            return {
                "Instances": [
                    {"InstanceArn": instance, "IdentityStoreId": "d-1234567890"}
                ]
            }

        def list_applications(self, **kw):
            return {
                "Applications": [{"ApplicationArn": application, "Status": "ENABLED"}]
            }

    monkeypatch.setattr(aws, "make_session", lambda *a: Fake())
    monkeypatch.setattr(aws, "configure_client_proxy", lambda client, *a: client)

    def call(session, region, host, service, target, body, **kw):
        if new_unavailable and target.startswith("KiroControl"):
            raise aws.AwsFailure("Read endpoint unavailable")
        return {"profiles": [profile]}, ""

    monkeypatch.setattr(aws, "signed_call", call)
    result = aws.discover(
        SimpleNamespace(
            access_key_id="test",
            secret_access_key="test",
            region="us-east-1",
            subscription_region="us-east-1",
        )
    )
    assert len(result["profiles"]) == 1
    assert result["profiles"][0]["control_plane"] == (
        "legacy" if new_unavailable else "kiro"
    )
    assert bool(result["warnings"]) == new_unavailable


@pytest.mark.parametrize(
    "plane,mode",
    [("legacy", "IMMEDIATE"), ("kiro", "IMMEDIATE"), ("kiro", "END_OF_PERIOD")],
)
def test_enterprise_cancellation_protocol(plane, mode, monkeypatch):
    g = gateway()
    g.account.control_plane = plane

    def post(url, **kw):
        body = {"principalId": "user-1", "principalType": "USER"}
        if plane == "kiro":
            body["deletionMode"] = mode
        assert json.loads(kw["data"]) == body
        assert (
            kw["headers"]["X-Amz-Target"]
            == (
                "KiroControlPlaneQDeveloperService"
                if plane == "kiro"
                else "AmazonQDeveloperService"
            )
            + ".DeleteAssignment"
        )
        assert "/us-east-1/q/aws4_request" in kw["headers"]["Authorization"]
        assert url == (
            "https://management.us-east-1.kiro.dev/"
            if plane == "kiro"
            else "https://codewhisperer.us-east-1.amazonaws.com/"
        )
        return SimpleNamespace(
            status_code=200,
            headers={"x-amzn-requestid": "cancel-request"},
            json=lambda: {},
        )

    patch_post(monkeypatch, post)
    assert (
        g.cancel_subscription(SimpleNamespace(sso_user_id="user-1"), mode)
        == "cancel-request"
    )


def test_public_identitystore_update_and_delete_only_target_saved_user():
    g = gateway()
    uid = "12345678-1234-1234-1234-123456789012"
    target = {"IdentityStoreId": "d-1234567890", "UserId": uid}
    with Stubber(g.identity) as stub:
        stub.add_response(
            "update_user",
            {},
            target
            | {
                "Operations": [
                    {"AttributePath": "displayName", "AttributeValue": "张三"},
                    {
                        "AttributePath": "emails",
                        "AttributeValue": [
                            {
                                "Value": "new@example.com",
                                "Primary": True,
                                "Type": "work",
                            }
                        ],
                    },
                ]
            },
        )
        stub.add_response("delete_user", {}, target)
        stub.add_client_error(
            "describe_user",
            service_error_code="ResourceNotFoundException",
            expected_params=target,
        )
        r = SimpleNamespace(sso_user_id=uid)
        g.update_user(r, "张三", "new@example.com")
        g.delete_user(r)
        assert g.user_info(r) is None
        stub.assert_no_pending_responses()


def test_subscription_snapshot_understands_alias_expiry_and_pending_downgrade(
    monkeypatch,
):
    g = gateway()
    claim = {
        "principal": {"user": "user-1"},
        "type": {"amazonQ": "KIRO_ENTERPRISE_PRO_MAX"},
        "expirationDate": 1800000000,
    }
    monkeypatch.setattr(g, "_claims", lambda token: {"claims": [claim]})
    info = g.subscription_info(SimpleNamespace(sso_user_id="user-1"))
    assert info["status"] == "cancelled" and info["expires_at"].year == 2027
    claim["newType"] = {"amazonQ": "KIRO_ENTERPRISE_PRO"}
    assert (
        g.subscription_info(SimpleNamespace(sso_user_id="user-1"))["status"] == "active"
    )
    assert (
        g.subscription_info(SimpleNamespace(sso_user_id="another"))["status"]
        == "not_subscribed"
    )
