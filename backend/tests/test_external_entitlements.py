"""Unmanaged logins need token-backed paid-plan evidence before JSON exists."""
import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.external_auth_models import ExternalExportItem
from app.external_auth_worker import run_one
from app.external_enterprise import ExternalEnterpriseAuth
from app.security import decrypt
from test_external_auth_batches import CompletedAuth, admit, completed, result_for


@pytest.mark.parametrize("subscription", [None, {}, {"type": "FREE"}, {"type": "UNKNOWN"},
    {"subscriptionTitle": "KIRO PRO"}, {"type": "Q_DEVELOPER_STANDALONE_PRO", "status": "CANCELLED"}])
def test_unmanaged_download_rejects_missing_free_or_unconfirmed_entitlement(alice, subscription):
    batch = admit(alice).json()
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        usage = result_for(item)["usage"]
    if subscription is not None:
        usage["subscriptionInfo"] = subscription
    else:
        usage.pop("subscriptionInfo", None)
    completed(batch, usage=usage)
    response = alice.post(f"/api/external-auth-batches/{batch['id']}/download")
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        item = db.scalar(select(ExternalExportItem))
        assert item.error_code == "paid_entitlement_unconfirmed"
        assert item.result_encrypted is None


def test_unmanaged_worker_does_not_persist_json_without_observed_paid_entitlement(alice):
    class WithoutEntitlement(CompletedAuth):
        def _advance(self, state, answer):
            super()._advance(state, answer)
            state["result"]["usage"].pop("subscriptionInfo", None)

    batch = admit(alice).json()
    assert run_one(auth_factory=WithoutEntitlement)
    assert run_one(auth_factory=WithoutEntitlement)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        assert item.state == "failed"
        assert item.error_code == "paid_entitlement_unconfirmed"
        assert item.result_encrypted is None


def test_unmanaged_adapter_stops_at_usage_without_publishing_done(monkeypatch):
    from test_external_auth_batches import TEXT
    from app.external_export_input import parse_accounts
    from app.external_enterprise import ExternalGateway
    from types import SimpleNamespace
    from app.identity_login import AuthError
    row = parse_accounts(TEXT)[0]
    item = SimpleNamespace(id="external-test", portal_url=row.portal_url, region=row.region)
    adapter = ExternalEnterpriseAuth(ExternalGateway(item, row.public(), lambda: None), checkpoint=lambda _: None)
    state = decrypt(adapter.begin(row.username, row.password.get_secret_value(), expected_user_id="actual-user").sealed_state)
    state.update(stage="usage", expected_user_id="actual-user", profile={"arn": "actual-profile"},
                 tokens={"accessToken": "synthetic-token"}, registration={})
    monkeypatch.setattr(adapter, "_request", lambda *args, **kw: {"userInfo": {"userId": "d-1234567890.actual-user"}})
    with pytest.raises(AuthError) as error:
        adapter._advance(state, None)
    assert error.value.code == "paid_entitlement_unconfirmed"
    assert state["stage"] == "usage" and "result" not in state
