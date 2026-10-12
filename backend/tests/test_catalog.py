from sqlalchemy import func, select

from app.database import SessionLocal
from app.init_db import initialize
from app.models import AuditEvent, Plan, PlanCounter


def test_catalog_upgrade_is_additive_and_repeatable():
    with SessionLocal() as db:
        pro = db.get(Plan, 1)
        pro.name = "团队专用 Pro"
        pro.active = False
        counter = db.get(PlanCounter, 1)
        counter.used_count, counter.lifetime_count = 1, 7
        db.commit()
    initialize()
    initialize()
    with SessionLocal() as db:
        plans = list(db.scalars(select(Plan)))
        assert len(plans) == 4
        assert db.get(Plan, 1).name == "团队专用 Pro"
        assert db.get(Plan, 1).active is False
        counter = db.get(PlanCounter, 1)
        assert (counter.limit_count, counter.used_count, counter.lifetime_count) == (
            2,
            1,
            7,
        )
        assert db.scalar(select(func.count()).select_from(PlanCounter)) == 3
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "sync_plan_catalog")
            )
            == 1
        )


def test_catalog_upgrade_preserves_custom_codes():
    with SessionLocal() as db:
        db.get(Plan, 1).code = "pro_max"
        db.commit()
    initialize()
    with SessionLocal() as db:
        assert db.get(Plan, 1).code == "pro_max"
        maximum = db.scalar(
            select(Plan).where(
                Plan.subscription_type == "Q_DEVELOPER_STANDALONE_PRO_MAX"
            )
        )
        assert maximum.code == "pro_max_2"


def test_catalog_reference_order_and_member_filter(admin, alice):
    initialize()
    catalog = admin.get("/api/plan-catalog").json()
    assert catalog["checked_at"] == "2026-09-24"
    plans = admin.get("/api/plans").json()
    assert [p["name"] for p in plans] == [
        "Kiro Pro",
        "Kiro Pro+",
        "Kiro Pro Max",
        "Kiro Power",
    ]
    assert [p["reference"]["monthly_price_usd"] for p in plans] == [20, 40, 100, 200]
    maximum = next(p for p in plans if p["code"] == "pro_max")
    assert maximum["reference"]["monthly_credits"] == 5000
    with SessionLocal() as db:
        db.get(Plan, maximum["id"]).active = False
        db.commit()
    assert maximum["id"] not in [p["id"] for p in alice.get("/api/plans").json()]


def test_new_tier_requires_its_own_admin_assigned_count(alice, admin):
    from test_workflows import Gateway, create
    from app.worker import run_one

    initialize()
    maximum = next(p for p in admin.get("/api/plans").json() if p["code"] == "pro_max")
    assert create(alice, plan=maximum["id"]).status_code == 409
    assert (
        admin.put(
            f"/api/admin/users/2/counters/{maximum['id']}", json={"limit_count": 1}
        ).status_code
        == 200
    )
    assert create(alice, plan=maximum["id"]).status_code == 202
    Gateway.mode = "ok"
    run_one(Gateway)
    assert create(alice, plan=maximum["id"]).status_code == 409
    counters = {c["plan_id"]: c for c in alice.get("/api/counters").json()}
    assert counters[maximum["id"]]["used_count"] == 1
    assert counters[1]["used_count"] == 0 and counters[2]["used_count"] == 0
