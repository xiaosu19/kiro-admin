"""Public CAPTCHA failures contain fixed descriptions and allowlisted codes."""
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import AuthJob, RecordOperation
from app.external_auth_models import ExternalExportItem
from app.security import encrypt
from test_auth_batches import admission, record
from test_external_auth_batches import admit as external_admit


CASES = [
    ("captcha_unavailable", "配置"),
    ("captcha_invalid_configuration", "配置"),
    ("captcha_provider_failed", "接口"),
    ("captcha_unsupported_challenge", "不支持"),
    ("captcha_attempt_limit", "次数"),
    ("captcha_timeout", "时间"),
    ("captcha_answer_rejected", "拒绝"),
]


@pytest.mark.parametrize("family", ["managed", "external"])
@pytest.mark.parametrize("code,description", CASES)
def test_workers_publish_code_specific_safe_captcha_description(alice, family, code, description):
    progress = SimpleNamespace(status="challenge", stage="workflow", revision=1, next_poll_at=None,
        sealed_state=encrypt({"captcha_automation": {"status": "requires_action", "reason": code}}))
    if family == "managed":
        from app.auth_jobs import claim_job, finish_step
        admission(alice, [record()])
        job_id, token = claim_job()
        finish_step(job_id, token, progress)
        with SessionLocal() as db:
            public_code = db.get(AuthJob, job_id).error_code
            public_error = db.get(RecordOperation, job_id).error
    else:
        from app.external_auth_worker import claim, finish
        batch = external_admit(alice).json()
        with SessionLocal() as db:
            item = db.get(ExternalExportItem, batch["items"][0]["id"])
            lane = item.lane_id
        item_id, token = claim(lane)
        finish(item_id, token, progress)
        with SessionLocal() as db:
            item = db.get(ExternalExportItem, item_id)
            public_code, public_error = item.error_code, item.error
    assert public_code == code
    assert description in public_error


def test_public_failure_keeps_last_safe_cause_without_echoing_unknown_codes(alice):
    from app.auth_jobs import claim_job, finish_step
    admission(alice, [record()])
    job_id, token = claim_job()
    progress = SimpleNamespace(status="challenge", stage="workflow", revision=1, next_poll_at=None,
        sealed_state=encrypt({"captcha_automation": {"status": "requires_action",
            "reason": "captcha_attempt_limit", "last_failure_code": "captcha_provider_failed"}}))
    finish_step(job_id, token, progress)
    with SessionLocal() as db:
        assert "接口" in db.get(RecordOperation, job_id).error
        assert db.get(AuthJob, job_id).error_code == "captcha_attempt_limit"


def test_public_failure_never_echoes_unrecognized_reason(alice):
    from app.auth_jobs import claim_job, finish_step
    admission(alice, [record()])
    job_id, token = claim_job()
    raw = "private endpoint cookie token and answer"
    progress = SimpleNamespace(status="challenge", stage="workflow", revision=1, next_poll_at=None,
        sealed_state=encrypt({"captcha_automation": {"status": "requires_action", "reason": raw,
                                                   "last_failure_code": raw}}))
    finish_step(job_id, token, progress)
    with SessionLocal() as db:
        assert db.get(AuthJob, job_id).error_code == "captcha_failed"
        assert raw not in db.get(RecordOperation, job_id).error
