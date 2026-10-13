"""Pasted SSO credentials using the existing native login and official OIDC flow.

No administrative AWS credentials are requested. Directory comes from the explicit
input or AWS portal name; user ID is frozen from authenticated whoAmI and checked
again against token-backed usage. Profiles are real API responses, never templates.
"""
import json
import re
import uuid
from types import SimpleNamespace

import boto3
import requests
from botocore import UNSIGNED
from botocore.config import Config

from .aws_transport import configure_client_proxy, request_session
from .config import settings
from .database import SessionLocal
from .enterprise_auth import EnterpriseAuth, verified_external_identity
from .identity_login import (
    AuthError,
    NativeIdentityLogin,
    _BootstrapHTML,
    _query,
    _url,
    require_text,
    require_number,
)
from .models import AwsAccount
from .proxies import ProxyUnavailable, check_account_proxy, proxy_selection
from .subscription_eligibility import has_observed_paid_entitlement
from .security import encrypt


class ExternalGateway:
    @staticmethod
    def account_for(item, configuration):
        profile_region = configuration['profile_arn'].split(':')[3] if configuration.get('profile_arn') else None
        return SimpleNamespace(
            id=item.id, portal_url=item.portal_url, region=item.region,
            identity_store_id=configuration['directory'],
            instance_arn=configuration.get('instance_arn'),
            profile_arn=configuration.get('profile_arn'),
            subscription_region=configuration.get('api_region') or profile_region or 'us-east-1',
        )

    def __init__(self, item, configuration, guard):
        self.account = self.account_for(item, configuration)
        self.proxy = None
        self._managed_account = None
        self.captcha_direct_allowed = not configuration.get('_managed_account_id')
        self._guard = guard
        if configuration.get('_managed_account_id'):
            try:
                with SessionLocal() as db:
                    account = db.get(AwsAccount, configuration['_managed_account_id'])
                    if not account:
                        raise ProxyUnavailable()
                    self.proxy = proxy_selection(db, account.proxy_id)
                    if (self.proxy.revision if self.proxy else None) != configuration['_managed_proxy_revision']:
                        raise ProxyUnavailable()
                    db.expunge(account)
                    self._managed_account = account
            except ProxyUnavailable:
                raise AuthError('proxy_unavailable') from None
        self.clients = []

    def _check_proxy(self):
        self._guard()
        if self._managed_account:
            try:
                check_account_proxy(self._managed_account, self.proxy)
            except ProxyUnavailable:
                raise AuthError('proxy_unavailable') from None

    def _client(self, service, *, region_name):
        if service != 'sso-oidc' or region_name != self.account.region:
            raise AuthError('unsafe_destination')
        self._check_proxy()
        client = boto3.client(service, region_name=region_name, config=Config(
            signature_version=UNSIGNED, connect_timeout=5, read_timeout=settings.aws_timeout,
            retries={'total_max_attempts': 1}, proxies={}))
        configure_client_proxy(client, self.proxy.url if self.proxy else None, self._check_proxy)
        self.clients.append(client)
        return client

    def close(self):
        for client in self.clients:
            client.close()


def discover_region(portal, guard):
    """One public GET (plus the portal's exact canonical slash redirect)."""
    url = portal
    try:
        with request_session() as session:
            for attempt in range(2):
                guard()
                with session.get(url, timeout=(5, settings.aws_timeout), allow_redirects=False,
                                 stream=True) as response:
                    if (attempt == 0 and response.status_code in (301, 302, 307, 308)
                            and response.headers.get('Location') in ('/start/', portal + '/')):
                        url = portal + '/'
                        continue
                    if response.status_code != 200:
                        raise AuthError('http_failed')
                    data = bytearray()
                    for chunk in response.iter_content(65536):
                        data.extend(chunk)
                        if len(data) > NativeIdentityLogin.MAX_BODY:
                            raise AuthError('invalid_response')
                    parser = _BootstrapHTML()
                    parser.feed(data.decode('utf-8', errors='replace'))
                    value = json.loads(''.join(parser.env_parts))
                    region = value.get('region')
                    if parser.env_count != 1 or not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
                        raise AuthError('invalid_response')
                    return region
        raise AuthError('unsafe_destination')
    except requests.RequestException:
        raise AuthError('transport_failed') from None
    except (ValueError, TypeError, KeyError):
        raise AuthError('invalid_response') from None


class ExternalEnterpriseAuth(EnterpriseAuth):
    # Existing AMS/OIDC helpers inspect this exact protocol kind. The immutable
    # job ID in the binding isolates external checkpoints from managed records.
    kind = 'enterprise'

    def _binding(self):
        a = self.gateway.account
        # The parser and public discovery already validate this immutable binding.
        return {'account_id': a.id, 'region': a.region, 'directory': a.identity_store_id,
                'instance': a.instance_arn, 'portal': a.portal_url,
                'api_region': a.subscription_region, 'profile_arn': a.profile_arn}

    def result_refresh_state(self, username, result, *, expected_user_id=None):
        """Use the original encrypted result's OIDC client, even for older jobs.

        Completed pasted jobs intentionally discard browser/login checkpoints.
        A refresh needs only the real saved registration and refresh token. No
        portal login, client registration, password change or device grant is
        recreated here. The worker rechecks the frozen owner/configuration too.
        """
        try:
            binding = self._binding()
            user_id = require_text(result['userId'], maximum=256, code='identity_mismatch')
            region = result['apiRegion']
            profile = result['profile']
            if (result['username'] != username or result['startUrl'] != binding['portal']
                    or result['authRegion'] != binding['region']
                    or result['identityStoreId'] != binding['directory']
                    or expected_user_id not in (None, user_id)
                    or region not in ('us-east-1', 'eu-central-1')
                    or not verified_external_identity(result['usage'], binding['directory'], user_id)
                    or not re.fullmatch(r'arn:aws:(?:codewhisperer|q|kiro):' + region
                        + r':\d{12}:profile/[A-Za-z0-9_-]+', profile['arn'])
                    or binding['profile_arn'] and profile['arn'] != binding['profile_arn']):
                raise AuthError('identity_mismatch')
            registration = {key: require_text(result[key], code='token_invalid')
                            for key in ('clientId', 'clientSecret')}
            registration['clientSecretExpiresAt'] = require_number(result['clientSecretExpiresAt'])
            if registration['clientSecretExpiresAt'] <= self.clock():
                raise AuthError('expired')
            tokens = {key: require_text(result[key], code='token_invalid')
                      for key in ('accessToken', 'refreshToken')}
            tokens['expiresAt'] = require_number(result['expiresAt'])
            password = result.get('password')
            if password is not None:
                require_text(password, maximum=1024, code='invalid_state')
            elif result.get('externalAuthorization') is not True:
                raise AuthError('invalid_state')
        except (KeyError, TypeError, ValueError):
            raise AuthError('invalid_state') from None
        credential = {'binding': {k: binding[k] for k in ('account_id', 'region', 'directory', 'instance')},
            'username': username, 'expected_user_id': user_id, 'current': password,
            'candidate': None, 'status': 'confirmed' if password else 'unknown', 'tried': []}
        return encrypt({'version': 1, 'kind': self.kind, 'binding': binding,
            'operation_id': str(uuid.uuid4()), 'username': username, 'expected_user_id': user_id,
            'credential': credential, 'registration': registration, 'tokens': tokens,
            'external_api_region': region, 'external_authorization': bool(result.get('externalAuthorization')),
            'profile': profile, 'refresh_profile_arn': profile['arn'],
            'result': result, 'stage': 'done', 'status': 'done',
            'revision': 0, 'steps': 0, 'cookies': [], 'inflight': None, 'challenge': None,
            'expires_at': tokens['expiresAt'], 'password_only': False, 'target_password': None,
            'recovering': False, 'password_changed': False})

    def begin_result_refresh(self, username, result, *, expected_user_id=None):
        return self.begin_refresh(self.result_refresh_state(
            username, result, expected_user_id=expected_user_id))

    def _new_state(self, *args, **kwargs):
        if kwargs.get('password_only'):
            raise AuthError('invalid_configuration')
        state = NativeIdentityLogin._new_state(self, *args, **kwargs)
        state.update(stage='register', operation_expires_at=state['expires_at'], polls=0,
                     pages=0, seen_pages=[], profiles=[], external_api_region=state['binding']['api_region'])
        return state

    def _advance(self, state, captcha_request):
        if state['stage'] == 'login' and state.get('dualstack') and not state['binding']['instance']:
            raise AuthError('invalid_configuration')
        if state['stage'] != 'usage':
            return super()._advance(state, captcha_request)
        region = state['external_api_region']
        usage = self._request(state, 'GET', f'https://management.{region}.kiro.dev/getUsageLimits',
            purpose='usage', headers={'Authorization': 'Bearer ' + state['tokens']['accessToken']},
            params={'profileArn': state['profile']['arn'], 'origin': 'AI_EDITOR', 'resourceType': 'AGENTIC_REQUEST'})
        if not verified_external_identity(usage, state['binding']['directory'], state['expected_user_id']):
            raise AuthError('identity_mismatch')
        if not getattr(self.gateway, '_managed_account', None) and not has_observed_paid_entitlement(usage):
            raise AuthError('paid_entitlement_unconfirmed')
        state['result'] = {
            **state['tokens'], **state['registration'], 'authRegion': state['binding']['region'],
            'apiRegion': region, 'startUrl': state['binding']['portal'], 'profile': state['profile'],
            'usage': usage, 'username': state['username'], 'userId': state['expected_user_id'],
            'password': state['credential']['current'], 'identityStoreId': state['binding']['directory'],
            'externalAuthorization': bool(state.get('external_authorization')),
        }
        state.update(stage='done', status='done')

    def _validate_target(self, state, url, purpose):
        if purpose in ('profiles', 'usage'):
            path = '/ListAvailableProfiles' if purpose == 'profiles' else '/getUsageLimits'
            if url != f"https://management.{state['external_api_region']}.kiro.dev{path}":
                raise AuthError('unsafe_destination')
            return
        return super()._validate_target(state, url, purpose)

    def _login_url(self, state, data):
        parsed = _url(require_text(data.get('redirectUrl')))
        b = state['binding']
        prefixes = {'/platform/' + b['directory']}
        if b['instance']:
            prefixes.add('/platform/' + b['instance'].split('/')[-1])
        if (parsed.netloc != b['region'] + '.signin.aws'
                or parsed.path not in {p + '/login' for p in prefixes} or parsed.fragment):
            raise AuthError('unsafe_destination')
        query = _query(parsed.query, {'workflowStateHandle'})
        state['start_handle'] = require_text(query.get('workflowStateHandle'))
        state['login_url'] = data['redirectUrl']
        state['execute_url'] = 'https://' + parsed.netloc + parsed.path.removesuffix('/login') + '/api/execute'
        state['csrf'] = require_text(data.get('csrfToken'))

    def _identity(self, state, data):
        require_text(data.get('userIdentifier'), maximum=256, code='identity_mismatch')
        user = require_text(data.get('identityStoreUserId', data.get('userIdentifier')),
                            maximum=256, code='identity_mismatch')
        if (data.get('directoryId') != state['binding']['directory']
                or state['expected_user_id'] not in (None, user)
                or any(data.get(k) is not None and data[k] != state['username'] for k in ('username', 'userName'))
                or data.get('userId') not in (None, user)):
            raise AuthError('identity_mismatch')
        state['expected_user_id'] = state['credential']['expected_user_id'] = user
        NativeIdentityLogin._identity(self, state, data)
        if state['credential']['status'] == 'current':
            state['credential']['status'] = 'confirmed'
            self._emit(state, 'password_confirmed', credential=True)

    def _profiles(self, state):
        if state['pages'] >= self.MAX_PAGES:
            raise AuthError('pagination_limit')
        region = state['external_api_region']
        data = self._request(state, 'POST', f'https://management.{region}.kiro.dev/ListAvailableProfiles',
            purpose='profiles', headers={'Authorization': 'Bearer ' + state['tokens']['accessToken']},
            json={'nextToken': state['next_page']} if state.get('next_page') else {})
        profiles = data.get('profiles')
        if not isinstance(profiles, list) or len(profiles) > 1000 or any(not isinstance(p, dict) for p in profiles):
            raise AuthError('invalid_response')
        state['pages'] += 1
        for profile in profiles:
            arn = profile.get('arn', '')
            if not isinstance(arn, str) or not re.fullmatch(r'arn:aws:(?:codewhisperer|q|kiro):' + region + r':\d{12}:profile/[A-Za-z0-9_-]+', arn):
                continue
            if state['binding']['profile_arn'] and arn != state['binding']['profile_arn']:
                continue
            if state.get('refresh_profile_arn') and arn != state['refresh_profile_arn']:
                continue
            details = profile.get('identityDetails') or {}
            if not isinstance(details, dict):
                raise AuthError('invalid_response')
            identity = details.get('ssoIdentityDetails') or {}
            if not isinstance(identity, dict):
                raise AuthError('invalid_response')
            if identity and (identity.get('ssoRegion', state['binding']['region']) != state['binding']['region']
                    or state['binding']['instance'] and identity.get('instanceArn') != state['binding']['instance']):
                continue
            state['profiles'].append(profile)
        next_token = data.get('nextToken')
        if next_token:
            require_text(next_token)
            if next_token in state['seen_pages']:
                raise AuthError('pagination_limit')
            state['seen_pages'].append(next_token)
            state['next_page'] = next_token
            return
        if not state['profiles'] and region == 'us-east-1' and not state['binding']['profile_arn']:
            state['external_api_region'] = 'eu-central-1'
            state['seen_pages'] = []
            state.pop('next_page', None)
            return
        if len(state['profiles']) != 1:
            raise AuthError('no_profile')
        state['profile'] = state['profiles'][0]
        require_text(state['profile'].get('profileName'))
        state['stage'] = 'usage'

    def _public_challenge(self, state):
        if (state.get('challenge') or {}).get('kind') == 'aws_authorization' and not state['expected_user_id']:
            # A manual browser may be logged in as someone else. Without a known
            # SSO ID it cannot be substituted for the isolated native login.
            challenge = state['challenge']
            return {k: v for k, v in challenge.items() if k in ('id', 'revision', 'expires_at')} | {'kind': 'requires_action'}
        return super()._public_challenge(state)

    def _answer(self, state, answer):
        if (answer or {}).get('continue_authorization') and not state['expected_user_id']:
            raise AuthError('identity_mismatch')
        return super()._answer(state, answer)
