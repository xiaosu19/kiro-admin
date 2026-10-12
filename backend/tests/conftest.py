import os
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet

TEST_DIR = Path(tempfile.mkdtemp(prefix="kiro-console-tests-"))
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DIR / 'test.db'}"
os.environ["SECRET_KEY"] = "test-session-key-" * 4
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["SECURE_COOKIE"] = "false"
os.environ["BACKUP_STATUS_PATH"] = str(TEST_DIR / "backup.json")
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["AWS_ACCESS_KEY_ID"] = "TEST_ACCESS_KEY"
os.environ["AWS_SECRET_ACCESS_KEY"] = "TEST_SECRET_KEY"
os.environ.pop("AWS_SESSION_TOKEN", None)

import pytest
from fastapi.testclient import TestClient
from app.database import Base, SessionLocal, engine
from app.models import AwsAccount, Binding, Plan, PlanCounter, User
from app.main import app
from app.security import encrypt, hash_password

PASSWORD = "test-password-12345"
HASH = hash_password(PASSWORD)


@pytest.fixture(autouse=True)
def forbid_unstubbed_sdk_wire(monkeypatch):
    from botocore.httpsession import URLLib3Session
    from requests.adapters import HTTPAdapter
    from urllib.parse import urlsplit

    def denied(*args, **kwargs):
        raise AssertionError("Tests must stub AWS SDK requests before network send")

    monkeypatch.setattr(URLLib3Session, "send", denied)
    original_send = HTTPAdapter.send

    def local_only(self, request, **kwargs):
        loopback = {"localhost", "127.0.0.1", "::1"}
        direct = urlsplit(request.url).hostname in loopback
        proxies = kwargs.get("proxies") or {}
        local_proxy = bool(proxies) and all(
            urlsplit(p).hostname in loopback for p in proxies.values()
        )
        if not (direct or local_proxy):
            raise AssertionError("Tests may only use local fake HTTP/SOCKS servers")
        return original_send(self, request, **kwargs)

    monkeypatch.setattr(HTTPAdapter, "send", local_only)


@pytest.fixture(autouse=True)
def database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add_all(
            [
                User(
                    id=1,
                    username="admin",
                    display_name="管理员",
                    role="admin",
                    password_hash=HASH,
                    must_change_password=False,
                ),
                User(
                    id=2,
                    username="alice",
                    display_name="用户 A",
                    role="member",
                    password_hash=HASH,
                    must_change_password=False,
                ),
                User(
                    id=3,
                    username="bob",
                    display_name="用户 B",
                    role="member",
                    password_hash=HASH,
                    must_change_password=False,
                ),
            ]
        )
        db.add_all(
            [
                Plan(
                    id=1,
                    name="Kiro Pro",
                    code="pro",
                    subscription_type="Q_DEVELOPER_STANDALONE_PRO",
                ),
                Plan(
                    id=2,
                    name="Kiro Pro+",
                    code="pro_plus",
                    subscription_type="Q_DEVELOPER_STANDALONE_PRO_PLUS",
                ),
            ]
        )
        db.add(
            AwsAccount(
                id=1,
                name="测试 AWS",
                aws_account_id="123456789012",
                region="us-east-1",
                subscription_region="us-east-1",
                control_plane="legacy",
                identity_store_id="d-1234567890",
                instance_arn="arn:aws:sso:::instance/ssoins-1234567890123456",
                application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890123456/apl-1234567890123456",
                profile_arn="arn:aws:codewhisperer:us-east-1:123456789012:profile/TEST",
                portal_url="https://d-1234567890.awsapps.com/start",
                credentials_encrypted=encrypt(
                    {
                        "access_key_id": "TEST_ACCESS_KEY",
                        "secret_access_key": "TEST_SECRET_KEY",
                    }
                ),
            )
        )
        db.commit()
        db.add_all(
            [
                Binding(user_id=2, aws_account_id=1),
                Binding(user_id=3, aws_account_id=1),
                PlanCounter(id=1, user_id=2, plan_id=1, limit_count=2),
                PlanCounter(id=2, user_id=2, plan_id=2, limit_count=1),
                PlanCounter(id=3, user_id=3, plan_id=1, limit_count=1),
            ]
        )
        db.commit()
    yield


def login(name):
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": name, "password": PASSWORD})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    return c


@pytest.fixture
def alice():
    return login("alice")


@pytest.fixture
def bob():
    return login("bob")


@pytest.fixture
def admin():
    return login("admin")
