"""Non-destructive initialization for this independent application's schema."""

import os
from sqlalchemy import select
from .catalog import CATALOG_CHECKED_AT, PAID_PLANS
from .database import Base, engine, SessionLocal
from .models import Plan, SchemaVersion, User
from .migrations import VERSION, migrate
from .security import audit, hash_password


def sync_plan_catalog(db):
    """Add missing tiers without changing existing plans, permissions or counts."""
    existing = list(db.scalars(select(Plan)))
    kinds = {p.subscription_type for p in existing}
    codes = {p.code for p in existing}
    added = []
    for tier in PAID_PLANS:
        if tier["subscription_type"] in kinds:
            continue
        code = tier["code"]
        suffix = 2
        while code in codes:
            code = f"{tier['code']}_{suffix}"
            suffix += 1
        db.add(
            Plan(
                name=tier["name"],
                code=code,
                subscription_type=tier["subscription_type"],
            )
        )
        codes.add(code)
        kinds.add(tier["subscription_type"])
        added.append(tier["name"])
    if added:
        audit(
            db,
            None,
            "sync_plan_catalog",
            f"按 {CATALOG_CHECKED_AT} 官方目录补充套餐：{'、'.join(added)}",
        )
    return added


def initialize():
    migrate(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        version = db.scalar(select(SchemaVersion))
        if version and version.version != VERSION:
            raise RuntimeError("数据库版本不匹配，请执行对应版本迁移")
        if not version:
            db.add(SchemaVersion(version=VERSION))
        if not db.scalar(select(User.id).where(User.role == "admin")):
            password = os.environ.get("ADMIN_PASSWORD")
            if not password:
                raise RuntimeError("首次初始化必须设置 ADMIN_PASSWORD")
            db.add(
                User(
                    username=os.environ.get("ADMIN_USERNAME", "admin"),
                    display_name="管理员",
                    password_hash=hash_password(password),
                    role="admin",
                    must_change_password=True,
                )
            )
        sync_plan_catalog(db)
        db.commit()
    print("数据库初始化与套餐目录同步完成。")


if __name__ == "__main__":
    initialize()
