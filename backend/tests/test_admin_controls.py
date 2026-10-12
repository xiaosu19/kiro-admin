from app.database import SessionLocal
from app.models import AuditEvent, CounterReset, PlanCounter
from sqlalchemy import func, select
from test_workflows import Gateway, count, create
from app.worker import run_one


def test_member_audit_hides_admin_and_other_actors(alice, bob, admin):
    with SessionLocal() as db:
        db.add_all(
            [
                AuditEvent(
                    actor_id=1,
                    actor_name="admin",
                    subject_user_id=2,
                    action="create_member",
                    detail="private admin action",
                ),
                AuditEvent(
                    actor_id=3,
                    actor_name="bob",
                    subject_user_id=2,
                    action="other",
                    detail="another person's action",
                ),
            ]
        )
        db.commit()
    own = alice.get("/api/audit").json()
    assert own["items"] and all(e["actor_name"] == "alice" for e in own["items"])
    assert "private admin action" not in alice.get("/api/audit").text
    assert "private admin action" in admin.get("/api/audit").text
    assert "private admin action" not in bob.get("/api/audit").text


def test_quick_reset_uses_current_saved_limit_and_preserves_lifetime(alice, admin):
    Gateway.mode = "ok"
    create(alice)
    run_one(Gateway)
    assert (
        admin.put("/api/admin/users/2/counters/1", json={"limit_count": 7}).status_code
        == 200
    )
    url = "/api/admin/users/2/counters/1/reset"
    assert alice.post(url, json={"expected_cycle": 1}).status_code == 403
    assert (
        admin.post(url, json={"expected_cycle": 1, "limit_count": 1000}).status_code
        == 422
    )
    assert admin.post(url, json={"expected_cycle": 1}).status_code == 200
    assert count() == (0, 0, 1, 2)
    with SessionLocal() as db:
        assert db.get(PlanCounter, 1).limit_count == 7
        row = db.scalar(select(CounterReset))
        assert row.previous_limit == row.new_limit == 7 and row.used_count == 1
    assert admin.post(url, json={"expected_cycle": 1}).status_code == 409
    assert count(2) == (0, 0, 0, 1)
    assert "reset_count" not in alice.get("/api/audit").text


def test_quick_reset_blocks_pending_and_unconfigured_plans(alice, admin):
    create(alice)
    assert (
        admin.post(
            "/api/admin/users/2/counters/1/reset", json={"expected_cycle": 1}
        ).status_code
        == 409
    )
    assert (
        admin.post(
            "/api/admin/users/3/counters/2/reset", json={"expected_cycle": 1}
        ).status_code
        == 404
    )
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(CounterReset)) == 0
