"""Three image protocols and public HTTPS socket pinning, all network-free."""
import asyncio
import base64
import json
import socket

import httpx
import pytest

from app.vision_captcha import VisionError, VisionProvider, normalize_endpoint
from app.vision_transport import PublicEndpointTransport, resolve_public
from test_vision_captcha import API_KEY, PNG, message


def response(protocol):
    if protocol == 'claude_messages':
        return message()
    if protocol == 'openai_chat':
        return {'choices': [{'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': 'aB34Zq'}}]}
    return {'status': 'completed', 'output': [
        {'type': 'reasoning', 'summary': []},
        {'type': 'message', 'role': 'assistant', 'status': 'completed',
         'content': [{'type': 'output_text', 'text': 'aB34Zq'}]},
    ]}


@pytest.mark.parametrize('protocol,suffix', [
    ('claude_messages', '/messages'), ('openai_chat', '/chat/completions'), ('openai_responses', '/responses'),
])
def test_three_protocols_send_only_image_fixed_instructions_and_own_key(protocol, suffix):
    calls = []
    def handler(request):
        calls.append(request)
        assert str(request.url) == 'https://vision.example.com/gateway/v1' + suffix
        body = json.loads(request.content)
        assert body['model'] == 'my-vision-model'
        data_uri = 'data:image/png;base64,' + base64.b64encode(PNG).decode()
        if protocol == 'claude_messages':
            assert request.headers['x-api-key'] == API_KEY
            assert 'authorization' not in request.headers
            assert body['messages'][0]['content'][0]['source']['data'] == base64.b64encode(PNG).decode()
        else:
            assert request.headers['authorization'] == 'Bearer ' + API_KEY
            assert 'x-api-key' not in request.headers
            if protocol == 'openai_chat':
                assert body['max_completion_tokens'] == 128
                assert body['messages'][1]['content'][0]['image_url']['url'] == data_uri
            else:
                assert body['input'][0]['content'][0]['image_url'] == data_uri
                assert body['max_output_tokens'] == 128 and body['store'] is False
        assert API_KEY.encode() not in request.content
        return httpx.Response(200, json=response(protocol))
    provider = VisionProvider(API_KEY, endpoint='https://vision.example.com/gateway/v1',
        protocol=protocol, model='my-vision-model', transport=httpx.MockTransport(handler))
    assert provider.recognize(PNG) == 'aB34Zq'
    assert len(calls) == 1


@pytest.mark.parametrize('protocol,body', [
    ('openai_chat', {'choices': []}),
    ('openai_chat', {'choices': [{'finish_reason': 'length', 'message': {'role': 'assistant', 'content': 'aB34Zq'}}]}),
    ('openai_chat', {'choices': [{'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': 'aB34Zq', 'tool_calls': [{}]}}]}),
    ('openai_chat', {'choices': [{'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': 'aB34Zq', 'refusal': 'refused'}}]}),
    ('openai_responses', {'status': 'incomplete', 'output': []}),
    ('openai_responses', {'status': 'completed', 'output': [{'type': 'function_call'}]}),
    ('openai_responses', {'status': 'completed', 'output': [{'type': 'message', 'role': 'assistant', 'content': [{'type': 'refusal', 'refusal': 'refused'}]}]}),
    ('openai_responses', {'status': 'completed', 'output': [], 'output_text': 'aB34Zq'}),
    ('openai_responses', {'status': 'completed', 'output': response('openai_responses')['output'], 'incomplete_details': {'reason': 'max_output_tokens'}}),
])
def test_refused_incomplete_tool_and_ambiguous_output_is_not_a_guess(protocol, body):
    provider = VisionProvider(API_KEY, endpoint='https://vision.example.com', protocol=protocol,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body)))
    with pytest.raises(VisionError, match='captcha_invalid_response'):
        provider.recognize(PNG)


@pytest.mark.parametrize('url', [
    'http://vision.example.com', 'https://127.0.0.1', 'https://10.0.0.1', 'https://169.254.169.254',
    'https://[::1]', 'https://[::ffff:8.8.8.8]', 'https://[64:ff9b::a00:1]',
    'https://224.0.0.1', 'https://[ff02::1]', 'https://[fec0::1]',
    'https://localhost', 'https://a.local', 'https://a.internal', 'https://bad..example.com',
    'https://a.example.com/v1/messages?key=secret', 'https://key:secret@a.example.com',
    'https://a.example.com/v1/chat/completions',
])
def test_unsafe_or_mismatched_endpoint_rejected_before_sending(url):
    with pytest.raises(VisionError, match='captcha_invalid_configuration'):
        normalize_endpoint(url, 'claude_messages')


@pytest.mark.parametrize('base', ['https://vision.example.com', 'https://vision.example.com/',
    'https://vision.example.com/v1', 'https://vision.example.com/v1/messages'])
def test_normalization_does_not_duplicate_v1_or_protocol(base):
    assert normalize_endpoint(base, 'claude_messages') == 'https://vision.example.com/v1/messages'


def test_dns_checked_once_then_numeric_socket_preserves_host_tls_sni_and_body(monkeypatch):
    async def scenario():
        calls, wire = [], []
        async def dns(host, port, **kwargs):
            calls.append((host, port))
            # A second resolution would change to loopback. No second lookup is allowed.
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8' if len(calls) == 1 else '127.0.0.1', port))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', dns)
        transport = PublicEndpointTransport()
        assert transport._inner._pool._ssl_context.check_hostname is True
        assert transport._inner._pool._ssl_context.verify_mode != 0
        await transport._inner.aclose()
        def handle(request):
            wire.append(request)
            assert request.url.host == '8.8.8.8'
            assert request.headers['host'] == 'vision.example.com:8443'
            assert request.extensions['sni_hostname'] == 'vision.example.com'
            assert request.content == b'only-image-payload'
            return httpx.Response(200, json={})
        transport._inner = httpx.MockTransport(handle)
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            await client.post('https://vision.example.com:8443/v1/messages', content=b'only-image-payload')
        assert calls == [('vision.example.com', 8443)] and len(wire) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize('addresses', [['127.0.0.1'], ['8.8.8.8', '10.0.0.1'], ['169.254.169.254'], ['::1'],
    ['224.0.0.1'], ['ff02::1'], ['fec0::1']])
def test_private_or_mixed_dns_answers_are_rejected(addresses, monkeypatch):
    async def scenario():
        async def dns(host, port, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (value, port)) for value in addresses]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', dns)
        with pytest.raises(httpx.ConnectError):
            await resolve_public('vision.example.com', 443)
    asyncio.run(scenario())
