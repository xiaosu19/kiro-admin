"""External AMS direct transport retains exact host, DNS pinning and TLS guards."""
import asyncio
import time
from types import SimpleNamespace

import httpx
import pytest

from app import captcha_browser, vision_transport

ROOT = 'us-east-1.threat-mitigation.aws.amazon.com'
CDN = 'cdn.' + ROOT
IMAGE = 'amcs-captcha-prod-us-east-1.s3.dualstack.us-east-1.amazonaws.com'


def direct_gateway():
    return SimpleNamespace(proxy=None, captcha_direct_allowed=True, _check_proxy=lambda: None)


def direct_http(gateway=None, hosts=None):
    return captcha_browser._ProxyHTTP(gateway or direct_gateway(), hosts or {ROOT, CDN}, time.monotonic() + 5,
                                     image_host=IMAGE, api_host=ROOT)


def test_external_direct_https_pins_public_ip_preserving_host_sni_and_tls(monkeypatch):
    observed = []
    async def resolve(host, port):
        assert host == ROOT and port == 443
        return '93.184.216.34'
    async def response(request):
        observed.append(request)
        assert request.url.host == '93.184.216.34'
        assert request.headers['host'] == ROOT
        assert request.extensions['sni_hostname'] == ROOT
        return httpx.Response(200, json={'safe': True})
    original = vision_transport.PublicEndpointTransport
    class LocalTransport(original):
        def __init__(self):
            self._inner = httpx.MockTransport(response)
    monkeypatch.setattr(vision_transport, 'resolve_public', resolve)
    monkeypatch.setattr(captcha_browser, 'PublicEndpointTransport', LocalTransport)
    async def scenario():
        async with direct_http() as transport:
            result = await transport.fetch('GET', 'https://' + ROOT + '/fixture', {}, None)
            assert result[0] == 200
    asyncio.run(scenario())
    assert len(observed) == 1


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '::ffff:93.184.216.34'])
def test_external_direct_rejects_nonpublic_dns_before_wire(monkeypatch, address):
    async def scenario():
        loop = asyncio.get_running_loop()
        async def dns(*args, **kwargs):
            return [(None, None, None, None, (address, 443))]
        monkeypatch.setattr(loop, 'getaddrinfo', dns)
        async with direct_http() as transport:
            with pytest.raises(captcha_browser.BrowserChallengeError) as error:
                await transport.fetch('GET', 'https://' + ROOT + '/fixture', {}, None)
            assert error.value.code == 'captcha_unsafe_destination'
    asyncio.run(scenario())


@pytest.mark.parametrize('proxy', [SimpleNamespace(url='http://127.0.0.1:9000'),
                                  SimpleNamespace(url='socks5://proxy.invalid:1080')])
def test_external_direct_never_falls_back_from_a_configured_invalid_proxy(proxy):
    gateway = direct_gateway()
    gateway.proxy = proxy
    with pytest.raises(captcha_browser.BrowserChallengeError):
        direct_http(gateway)


def test_external_direct_only_accepts_exact_official_regional_hosts():
    with pytest.raises(captcha_browser.BrowserChallengeError):
        direct_http(hosts={ROOT, CDN, 'evil.invalid'})


def test_external_direct_checks_revocation_before_any_wire(monkeypatch):
    revoked = RuntimeError('synthetic revocation')
    def guard():
        raise revoked
    gateway = direct_gateway()
    gateway._check_proxy = guard
    async def scenario():
        async with direct_http(gateway) as transport:
            with pytest.raises(RuntimeError) as error:
                await transport.fetch('GET', 'https://' + ROOT + '/fixture', {}, None)
            assert error.value is revoked
    asyncio.run(scenario())


def test_external_direct_keeps_ordinary_network_failure_distinct_from_unsafe_dns(monkeypatch):
    async def resolve(*args):
        raise httpx.ConnectError('synthetic ordinary connection failure')
    monkeypatch.setattr(vision_transport, 'resolve_public', resolve)
    async def scenario():
        async with direct_http() as transport:
            with pytest.raises(captcha_browser.BrowserChallengeError) as error:
                await transport.fetch('GET', 'https://' + ROOT + '/fixture', {}, None)
            assert error.value.code == 'captcha_browser_failed'
            assert 'synthetic' not in str(error.value)
    asyncio.run(scenario())
