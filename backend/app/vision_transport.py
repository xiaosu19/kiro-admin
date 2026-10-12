"""Resolve public provider addresses once and pin HTTPS to the checked socket.

Preserve the original Host, SNI and certificate verification. Do not inherit
environment proxies, follow redirects, or retry requests that might be billed.
"""
import asyncio
from ipaddress import ip_address, ip_network
import socket

import httpx


def public_address(value):
    address = ip_address(value)
    if (not address.is_global or address.is_multicast or getattr(address, "is_site_local", False)
        or getattr(address, "ipv4_mapped", None)):
        return False
    if address.version == 6 and (
        address.sixtofour or address.teredo
        or address in ip_network("64:ff9b::/96")
        or address in ip_network("64:ff9b:1::/48")
    ):
        return False
    return True


async def resolve_public(host, port):
    try:
        ip_address(host)
        addresses = [host]
    except ValueError:
        records = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
        )
        addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or any(not public_address(value) for value in addresses):
        raise httpx.ConnectError("Provider address is not public")
    return addresses[0]


class PublicEndpointTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self._inner = httpx.AsyncHTTPTransport(
            verify=True, trust_env=False, retries=0, http2=False,
        )

    async def handle_async_request(self, request):
        if request.url.scheme != "https":
            raise httpx.ConnectError("Provider requires HTTPS")
        host = request.url.host
        address = await resolve_public(host, request.url.port or 443)
        headers = request.headers.copy()
        headers["Host"] = request.url.netloc.decode("ascii")
        pinned = httpx.Request(
            request.method, request.url.copy_with(host=address),
            headers=headers, stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host},
        )
        return await self._inner.handle_async_request(pinned)

    async def aclose(self):
        await self._inner.aclose()
