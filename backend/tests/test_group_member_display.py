"""Batch detail identifies historical members without separate record requests."""

from app.database import SessionLocal
from app.models import GroupJob, Subscription
from test_group_member_batches import admitted, get_batch, prepare, route
from test_native_groups import native


def test_stopped_batch_keeps_scoped_member_names_after_reload(alice, bob, native):
    ids = prepare(alice, count=2)
    batch = admitted(alice, ids)
    assert batch["items"][0]["username"] == ids[0]
    assert batch["items"][0]["sso_user_id"] == "sso-" + ids[0]
    assert alice.post(route(batch, "stop")).status_code == 200
    refreshed = get_batch(alice, batch)
    assert [item["username"] for item in refreshed["items"]] == ids
    assert all(item["state"] == "stopped" for item in refreshed["items"])
    assert bob.get(route(batch)).status_code == 404
    # A changed ownership mapping must not disclose its current private name.
    with SessionLocal() as db:
        record = db.get(Subscription, ids[0])
        record.owner_id, record.username = 3, "other-owner-secret"
        db.commit()
    refreshed = get_batch(alice, batch)
    assert refreshed["items"][0]["username"] is None
    assert "other-owner-secret" not in str(refreshed)


def test_job_batch_links_follow_existing_actor_visibility(alice, admin, native):
    ids = prepare(alice, count=1)
    batch = admitted(admin, ids)
    with SessionLocal() as db:
        db.add(GroupJob(id="legacy", group_id="group-1", record_id=ids[0], actor_id=2,
                        kind="attach", request_key="legacy-history", payload="{}", state="failed"))
        db.commit()
    jobs = admin.get("/api/groups/group-1/jobs").json()
    assert next(job for job in jobs if job["id"] == "legacy")["member_batch_id"] is None
    assert next(job for job in jobs if job["id"] == batch["items"][0]["job_id"])["member_batch_id"] == batch["id"]
    owned = alice.get("/api/groups/group-1/jobs").json()
    assert [job["id"] for job in owned] == ["legacy"]
    assert batch["id"] not in str(owned)
