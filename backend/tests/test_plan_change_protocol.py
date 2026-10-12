"""Protocol pinned to AWS console UpdateAssignment and claim mapper, 2026-10-10."""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.aws import AwsFailure
from test_aws_adapter import gateway, patch_post
from test_plan_changes import PRO, PLUS


@pytest.mark.parametrize(
    "plane,host,prefix",
    [
        ("legacy", "codewhisperer.us-east-1.amazonaws.com", "AmazonQDeveloperService"),
        ("kiro", "management.us-east-1.kiro.dev", "KiroControlPlaneQDeveloperService"),
    ],
)
def test_update_assignment_wire_is_signed_q_via_existing_transport(
    monkeypatch, plane, host, prefix
):
    seen = []

    def post(url, **kwargs):
        seen.append(url)
        assert url == f"https://{host}/"
        assert kwargs["headers"]["X-Amz-Target"] == prefix + ".UpdateAssignment"
        assert "/us-east-1/q/aws4_request" in kwargs["headers"]["Authorization"]
        assert kwargs["allow_redirects"] is False
        assert json.loads(kwargs["data"]) == {
            "principalId": "existing-id",
            "principalType": "USER",
            "subscriptionType": PLUS,
        }
        return SimpleNamespace(
            status_code=200,
            headers={"x-amzn-requestid": "change-request"},
            json=lambda: {},
        )

    patch_post(monkeypatch, post)
    g = gateway()
    g.account.control_plane = plane
    assert hasattr(g, "update_assignment"), "Gateway must expose UpdateAssignment"
    assert (
        g.update_assignment(SimpleNamespace(sso_user_id="existing-id"), PLUS)
        == "change-request"
    )
    assert len(seen) == 1


def claim(current="KIRO_ENTERPRISE_PRO_PLUS", pending="KIRO_ENTERPRISE_PRO"):
    return {
        "principal": {"user": "user-1"},
        "type": {"amazonQ": current},
        "newType": {"amazonQ": pending} if pending else {},
        "expirationDate": "2026-11-01T00:00:00Z",
    }


def test_rich_claim_retains_current_pending_and_estimated_period_end(monkeypatch):
    g = gateway()
    monkeypatch.setattr(g, "_claims", lambda token=None: {"claims": [claim()]})
    assert hasattr(g, "plan_change_info"), (
        "Gateway must expose separate rich claim observation"
    )
    assert g.plan_change_info(SimpleNamespace(sso_user_id="user-1")) == {
        "status": "active",
        "current_type": PLUS,
        "pending_type": PRO,
        "expected_effective_at": datetime(2026, 11, 1),
    }
    assert g.subscription_info(SimpleNamespace(sso_user_id="user-1")) == {
        "status": "active",
        "subscription_type": PLUS,
        "expires_at": None,
        "pending_type": PRO,
        "expected_effective_at": datetime(2026, 11, 1),
    }


@pytest.mark.parametrize(
    "claims",
    [
        [claim(), claim()],
        [claim(current="UNKNOWN")],
        [claim(pending="UNKNOWN")],
        [claim(current="KIRO_ENTERPRISE_PRO", pending="KIRO_ENTERPRISE_PRO_PLUS")],
    ],
)
def test_rich_claim_rejects_ambiguous_or_unknown_data(monkeypatch, claims):
    g = gateway()
    monkeypatch.setattr(g, "_claims", lambda token=None: {"claims": claims})
    assert hasattr(g, "plan_change_info")
    with pytest.raises(AwsFailure) as exc:
        g.plan_change_info(SimpleNamespace(sso_user_id="user-1"))
    assert exc.value.uncertain


def test_rich_claim_paginates_ignores_other_principals_and_detects_loop(monkeypatch):
    g = gateway()
    pages = [
        {
            "claims": [
                {"principal": {"user": "other"}, "type": {"amazonQ": "UNKNOWN"}}
            ],
            "nextToken": "two",
        },
        {"claims": [claim(pending=None)]},
    ]
    monkeypatch.setattr(g, "_claims", lambda token=None: pages.pop(0))
    assert hasattr(g, "plan_change_info")
    result = g.plan_change_info(SimpleNamespace(sso_user_id="user-1"))
    assert result["status"] == "cancelled" and result["pending_type"] is None
    assert result["expected_effective_at"] is None
    monkeypatch.setattr(
        g, "_claims", lambda token=None: {"claims": [], "nextToken": "two"}
    )
    with pytest.raises(AwsFailure):
        g.plan_change_info(SimpleNamespace(sso_user_id="user-1"))
