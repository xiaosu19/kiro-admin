from datetime import datetime

import pytest

from app.database import SessionLocal
from app.models import Subscription, now


def seed_directory():
    with SessionLocal() as db:
        for owner, size in ((2, 105), (3, 5)):
            for i in range(size):
                key = f"selection-{owner}-{i:03}"
                db.add(
                    Subscription(
                        id=key,
                        request_key=key,
                        owner_id=owner,
                        aws_account_id=1,
                        username=key,
                        email=f"{key}@example.com",
                        sso_user_id=f"sso-{key}",
                        portal_url="https://example.awsapps.com/start",
                        provision_only=True,
                        state="completed",
                        reserved=False,
                        created_at=datetime(2026, 9, 24),
                        sso_deleted_at=now() if i == 104 else None,
                    )
                )
        db.commit()


def test_filtered_selection_is_bounded_and_cannot_select_another_owner(
    alice, bob, admin
):
    seed_directory()
    base = "/api/sso-users?page_size=100"
    first = alice.get(base + "&owner_id=3").json()
    assert first["total"] == 105 and first["page_size"] == 100
    assert len(first["items"]) == 100
    assert all(r["owner_id"] == 2 for r in first["items"])
    second = alice.get(base + "&page=2").json()
    assert len(second["items"]) == 5
    ids = [r["id"] for r in first["items"] + second["items"]]
    assert len(set(ids)) == 105  # Equal timestamps cannot cause page overlap.
    assert first["items"][0]["id"] == "selection-2-104"
    assert bob.get(base + "&owner_id=2").json()["total"] == 5
    assert admin.get(base + "&owner_id=3").json()["total"] == 5
    assert admin.get(base).json()["total"] == 110
    assert "password_encrypted" not in alice.get(base).text
    regular = alice.get("/api/sso-users").json()
    assert regular["page_size"] == 30 and len(regular["items"]) == 30


def test_selection_uses_the_same_search_and_status_as_directory(alice):
    seed_directory()
    deleted = alice.get("/api/sso-users?page_size=100&status=deleted").json()
    assert deleted["total"] == 1 and deleted["items"][0]["id"] == "selection-2-104"
    active = alice.get(
        "/api/sso-users?page_size=100&status=active&q=selection-2-10"
    ).json()
    assert active["total"] == 4 and all(
        not r["sso_deleted_at"] for r in active["items"]
    )
    empty = alice.get("/api/sso-users?page_size=100&q=selection-3").json()
    assert empty["items"] == [] and empty["total"] == 0


@pytest.mark.parametrize("size", [0, -1, 101, 10000])
def test_selection_page_size_rejects_invalid_or_unbounded_requests(alice, size):
    assert alice.get(f"/api/sso-users?page_size={size}").status_code == 422
