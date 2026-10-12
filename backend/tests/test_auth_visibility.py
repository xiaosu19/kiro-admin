"""Auth jobs remain actor-private through the legacy record projections."""

import uuid
from datetime import timedelta

import pytest

from app.database import SessionLocal
from app.main import subscription_view
from app.models import ManagedGroup, RecordOperation, Subscription, User, now
from conftest import login
from test_auth_batches import admission, record


@pytest.fixture
def clients(alice, admin):
    with SessionLocal() as db:
        db.add(
            User(
                id=4,
                username="other-admin",
                display_name="Other administrator",
                role="admin",
                password_hash=db.get(User, 1).password_hash,
                must_change_password=False,
            )
        )
        db.commit()
    return {"alice": alice, "admin": admin, "other-admin": login("other-admin")}


def grouped_record():
    r = record()
    gid = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(
            ManagedGroup(
                id=gid,
                owner_id=r.owner_id,
                aws_account_id=r.aws_account_id,
                aws_scope="test-scope",
                request_key=gid,
                payload_hash="test-hash",
                name="Visibility test group",
                marker="test-marker",
                state="ready",
            )
        )
        db.flush()
        db.get(Subscription, r.id).group_id = gid
        db.commit()
    return r, gid


def projections(client, r, gid):
    result = {}
    for path, field in (
        (f"/api/subscriptions/{r.id}", None),
        ("/api/subscriptions", "items"),
        ("/api/sso-users", "items"),
        (f"/api/groups/{gid}", "members"),
    ):
        response = client.get(path)
        assert response.status_code == 200, response.text
        value = response.json()
        result[path] = (
            next(item for item in value[field] if item["id"] == r.id)
            if field
            else value
        )
    return result


@pytest.mark.parametrize(
    "kind", ["json_export", "reset_password", "random_password", "custom_password"]
)
@pytest.mark.parametrize(
    "initiator,viewer",
    [("alice", "admin"), ("admin", "alice"), ("admin", "other-admin")],
)
def test_auth_operations_are_actor_private_in_all_legacy_views(
    clients, kind, initiator, viewer
):
    r, gid = grouped_record()
    actor, observer = clients[initiator], clients[viewer]
    response = admission(
        actor,
        [r],
        kind,
        **({"password": "TestCustom1!"} if kind == "custom_password" else {}),
    )
    assert response.status_code == 202, response.text
    batch = response.json()
    op_id = batch["items"][0]["operation_id"]
    assert observer.get(f"/api/auth-batches/{batch['id']}").status_code == 404

    for value in projections(actor, r, gid).values():
        assert value["operation"]["id"] == op_id
    own_history = actor.get(f"/api/subscriptions/{r.id}/operations").json()
    assert [op["id"] for op in own_history] == [op_id]

    visible = projections(observer, r, gid)
    history = observer.get(f"/api/subscriptions/{r.id}/operations")
    assert history.status_code == 200
    leaked = [path for path, value in visible.items() if value["operation"]]
    if history.json():
        leaked.append("operation history")
    assert leaked == [], f"Other actor's auth metadata exposed through {leaked}"
    for value in visible.values():
        assert value["operation_pending"] is True
        assert op_id not in str(value)

    # The legacy retry API must not bypass auth-batch ownership or resume rules.
    for client in (actor, observer):
        response = client.post(
            f"/api/subscriptions/{r.id}/operations/{op_id}/retry",
            json={"confirm_username": r.username},
        )
        assert response.status_code == 404


def test_auth_history_is_filtered_before_limit_without_hiding_normal_jobs(admin):
    r = record()
    own_id, normal_id = str(uuid.uuid4()), str(uuid.uuid4())
    with SessionLocal() as db:
        db.add_all(
            [
                RecordOperation(
                    id=str(uuid.uuid4()),
                    record_id=r.id,
                    actor_id=2,
                    kind="auth_json_export",
                    request_key=str(uuid.uuid4()),
                    payload="{}",
                    state="completed",
                    created_at=now(),
                )
                for _ in range(101)
            ]
            + [
                RecordOperation(
                    id=oid,
                    record_id=r.id,
                    actor_id=actor_id,
                    kind=kind,
                    request_key=oid,
                    payload="{}",
                    state="completed",
                    created_at=now() - timedelta(days=1),
                )
                for oid, actor_id, kind in (
                    (own_id, 1, "auth_reset_password"),
                    (normal_id, 2, "reset_password"),
                )
            ]
        )
        db.commit()
    response = admin.get(f"/api/subscriptions/{r.id}/operations")
    assert response.status_code == 200
    assert {op["id"] for op in response.json()} == {own_id, normal_id}


@pytest.mark.parametrize("viewer", ["admin", "other-admin"])
def test_normal_lifecycle_jobs_retain_cross_actor_admin_visibility(clients, viewer):
    r, gid = grouped_record()
    body = {"kind": "sync_status", "request_key": str(uuid.uuid4())}
    response = clients["alice"].post(
        f"/api/subscriptions/{r.id}/operations", json=body
    )
    assert response.status_code == 202, response.text
    op_id = response.json()["id"]
    observer = clients[viewer]
    for value in projections(observer, r, gid).values():
        assert value["operation"]["id"] == op_id
        assert value["operation_pending"] is True
    history = observer.get(f"/api/subscriptions/{r.id}/operations").json()
    assert [op["id"] for op in history] == [op_id]
    assert history[0]["actor_name"] == "用户 A"
    retry = observer.post(
        f"/api/subscriptions/{r.id}/operations/{op_id}/retry",
        json={"confirm_username": r.username},
    )
    assert retry.status_code == 202
    assert retry.json()["id"] == op_id


def test_omitted_viewer_cannot_expose_an_auth_operation(alice):
    r = record()
    assert admission(alice, [r]).status_code == 202
    with SessionLocal() as db:
        value = subscription_view(db.get(Subscription, r.id), db)
    assert value["operation_pending"] is True
    assert value["operation"] is None
