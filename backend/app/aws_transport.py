"""Per-client SOCKS5 transport for botocore and custom SigV4 HTTP requests.

Botocore's urllib3 proxy manager does not implement SOCKS. Requests' SOCKS
adapter does; return AWSResponse so botocore keeps signing and response parsing.
No environment proxies, redirects, implicit retries, or global socket changes.
"""

import requests
from botocore.awsrequest import AWSResponse
from botocore.exceptions import (
    ConnectTimeoutError,
    EndpointConnectionError,
    HTTPClientError,
    ReadTimeoutError,
    SSLError,
)
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from .config import settings


def request_session(proxy_url=None):
    session = requests.Session()
    session.trust_env = False
    session.verify = True
    session.mount("http://", HTTPAdapter(max_retries=0))
    session.mount("https://", HTTPAdapter(max_retries=0))
    if proxy_url:
        if not proxy_url.startswith("socks5h://"):
            raise ValueError("代理必须使用 SOCKS5 远端 DNS")
        session.proxies = {"http": proxy_url, "https": proxy_url}
    return session


class _ClientTransport:
    def __init__(self, proxy_url, guard=None, verify=True):
        self.session = request_session(proxy_url)
        self.guard = guard
        self.before_send = None
        self.verify = verify

    def send(self, request):
        if self.guard:
            self.guard()
        # Botocore already encoded and signed the complete URL, headers and body.
        # Session.request would requote %7E to '~', invalidating those signatures.
        prepared = requests.PreparedRequest()
        prepared.method, prepared.url = request.method, request.url
        prepared.headers = CaseInsensitiveDict(request.headers)
        prepared.body = request.body
        if self.before_send:
            self.before_send(request)
        try:
            # Session.send pre-processes redirects even when following is disabled,
            # consuming their raw bodies. The adapter preserves every AWS response
            # and has no redirect handling; botocore remains the sole parser.
            response = self.session.get_adapter(request.url).send(
                prepared,
                timeout=(5, settings.aws_timeout),
                verify=self.verify,
                stream=True,
                proxies=self.session.proxies,
            )
        except requests.ConnectTimeout:
            raise ConnectTimeoutError(endpoint_url=request.url) from None
        except requests.ReadTimeout:
            raise ReadTimeoutError(endpoint_url=request.url) from None
        except requests.exceptions.SSLError:
            raise SSLError(
                endpoint_url=request.url, error="TLS verification failed"
            ) from None
        except requests.ConnectionError:
            raise EndpointConnectionError(endpoint_url=request.url) from None
        except requests.RequestException:
            raise HTTPClientError(error="AWS transport failed") from None
        return AWSResponse(
            request.url, response.status_code, response.headers, response.raw
        )

    def close(self):
        self.session.close()


def configure_client_proxy(client, proxy_url=None, guard=None):
    """Replace only this client's wire transport; preserve botocore event/parser flow."""
    previous = client._endpoint.http_session
    # Honor an explicitly configured CA bundle; TLS verification is always enabled.
    verify = getattr(previous, "_verify", True)
    client._endpoint.http_session = _ClientTransport(
        proxy_url, guard, verify if isinstance(verify, str) else True
    )
    previous.close()
    return client
