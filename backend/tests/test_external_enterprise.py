"""The external adapter reuses the native protocol and binds returned identities."""
import pytest

from app.external_enterprise import ExternalEnterpriseAuth
from app.identity_login import AuthError
from app.security import decrypt
from test_enterprise_auth import Oidc
from test_identity_login import (DP, EXECUTE, NOW, OIDC, Gateway, Script,
                                key_context as key_context, opening, run_ready, success, workflow)


def setup(monkeypatch, context):
    gateway = Gateway()
    gateway.account.instance_arn = None
    gateway.account.profile_arn = None
    gateway.account.subscription_region = 'us-east-1'
    gateway.oidc = Oidc()
    script = opening(Script(monkeypatch, gateway), workflow('get-password', context))
    script.add('POST', EXECUTE, success())
    script.add('POST', DP + '/auth/sso-token', {'token': 'portal-secret'})
    script.add('GET', DP + '/token/whoAmI', {'userIdentifier': 'opaque',
               'identityStoreUserId': 'actual-sso-id', 'directoryId': 'd-1234567890', 'username': 'alice'})
    script.add('POST', DP + '/session/device', {'token': 'session-secret'})
    script.add('POST', OIDC + '/device_authorization/accept_user_code', {
        'deviceContext': {'deviceContextId': 'our-context', 'clientId': 'our-client', 'clientType': 'public'}})
    script.add('POST', OIDC + '/device_authorization/associate_token', {})
    clock = [NOW]
    adapter = ExternalEnterpriseAuth(gateway, checkpoint=lambda e: None, clock=lambda: clock[0])
    return adapter, adapter.begin('alice', 'old-secret'), script, clock


def test_discovers_real_identity_profile_and_usage_without_admin_metadata(monkeypatch, key_context):
    adapter, progress, script, clock = setup(monkeypatch, key_context[1])
    profile = {'arn': 'arn:aws:codewhisperer:us-east-1:123456789012:profile/actual',
               'profileName': 'Actual AWS profile', 'identityDetails': None}
    usage = {'userInfo': {'userId': 'd-1234567890.actual-sso-id', 'email': 'actual@example.test'},
             'subscriptionInfo': {'type': 'Q_DEVELOPER_STANDALONE_PRO'}}
    script.add('POST', 'https://management.us-east-1.kiro.dev/ListAvailableProfiles', {'profiles': [profile]})
    script.add('GET', 'https://management.us-east-1.kiro.dev/getUsageLimits', usage)
    progress = run_ready(adapter, progress)
    assert progress.status == 'polling'
    clock[0] = progress.next_poll_at
    done = run_ready(adapter, adapter.advance(progress.sealed_state))
    assert done.status == 'done' and not script.steps
    assert done.result['userId'] == 'actual-sso-id'
    assert done.result['profile'] == profile and done.result['usage'] == usage
    assert done.result['password'] == 'old-secret'
    assert done.result['authRegion'] == done.result['apiRegion'] == 'us-east-1'


def test_wrong_whoami_username_stops_before_device_authorization():
    gateway = Gateway()
    adapter = ExternalEnterpriseAuth(gateway, checkpoint=lambda e: None, clock=lambda: NOW)
    state = decrypt(adapter.begin('alice', 'old-secret').sealed_state)
    with pytest.raises(AuthError, match='身份'):
        adapter._identity(state, {'userIdentifier': 'u', 'identityStoreUserId': 'u',
                                'directoryId': 'd-1234567890', 'username': 'bob'})


def test_ambiguous_profiles_and_usage_mismatch_are_not_exported(monkeypatch, key_context):
    adapter, progress, script, clock = setup(monkeypatch, key_context[1])
    profiles = [{'arn': f'arn:aws:codewhisperer:us-east-1:123456789012:profile/{i}',
                 'profileName': 'Actual'} for i in ('one', 'two')]
    script.add('POST', 'https://management.us-east-1.kiro.dev/ListAvailableProfiles', {'profiles': profiles})
    progress = run_ready(adapter, progress)
    clock[0] = progress.next_poll_at
    with pytest.raises(AuthError, match='profile'):
        run_ready(adapter, adapter.advance(progress.sealed_state))
