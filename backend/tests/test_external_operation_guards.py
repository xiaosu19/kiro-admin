"""Managed pasted login remains an explicit busy operation for other modules."""
import pytest
from fastapi import HTTPException

from app.database import SessionLocal
from app.external_auth_models import ExternalExportItem
from app.models import ManagedGroup, Subscription, User
from test_external_auth_batches import admit
from test_external_managed_login import managed_record


@pytest.mark.parametrize('state', ['queued', 'running', 'polling', 'challenge'])
@pytest.mark.parametrize('family', ['lifecycle', 'plan', 'member'])
def test_managed_pasted_login_blocks_conflicting_operation_admission(alice, state, family):
    record = managed_record()
    response = admit(alice)
    assert response.status_code == 202
    with SessionLocal() as db:
        db.get(ExternalExportItem, response.json()['items'][0]['id']).state = state
        db.commit()
        current, actor = db.get(Subscription, record.id), db.get(User, 2)
        with pytest.raises(HTTPException) as raised:
            if family == 'lifecycle':
                from app.lifecycle import validate_operation
                validate_operation(db, current, actor, 'reset_password')
            elif family == 'plan':
                from app.plan_changes import admission_owner
                admission_owner(db, current, actor)
            else:
                from app.group_members import validate_member
                validate_member(db, ManagedGroup(id='unused-group'), current.id, actor, 'attach')
        assert raised.value.status_code == 409
        assert '粘贴账号认证任务' in raised.value.detail
