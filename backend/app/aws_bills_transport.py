"""Per-operation socket deadlines for Bills' requests transport.

Requests' read timeout restarts on each recv, including the repeated reads
inside HTTP headers, chunk framing and SOCKS negotiation. Keep those reads
under one deadline without changing global sockets or leaving worker threads.
"""

import io
import socket
import time
from http.client import HTTPResponse

import socks
from requests.adapters import HTTPAdapter
from urllib3.contrib.socks import SOCKSConnection
from urllib3.exceptions import NewConnectionError


def _remaining(deadline, limit):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("AWS Bills transport deadline exceeded")
    return min(limit, remaining)


class _DeadlineReader(io.RawIOBase):
    def __init__(self, raw, sock, deadline):
        self.raw, self.sock, self.deadline = raw, sock, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        # BufferedReader.readline can invoke this many times before returning
        # a single header/chunk line to either http.client or urllib3.
        self.sock.settimeout(_remaining(self.deadline, 30))
        return self.raw.readinto(buffer)

    def fileno(self):
        return self.raw.fileno()

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class _DeadlineSocksSocket(socks.socksocket):
    def __init__(self, *args, deadline, **kwargs):
        super().__init__(*args, **kwargs)
        self.deadline = deadline

    def _arm(self):
        self.settimeout(_remaining(self.deadline, 5))

    def connect(self, *args, **kwargs):
        self._arm()
        return super().connect(*args, **kwargs)

    def recv_into(self, *args, **kwargs):
        # PySocks uses an unbuffered SocketIO in _readall, which calls this for
        # each partial greeting, authentication or bound-address response.
        self._arm()
        return super().recv_into(*args, **kwargs)

    def send(self, *args, **kwargs):
        self._arm()
        return super().send(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        self._arm()
        return super().sendall(*args, **kwargs)


def _proxy_socket(connection, deadline):
    """Use PySocks' protocol with a socket subclass private to this client."""
    options = connection._socks_options
    host = options["proxy_host"].strip("[]")
    port = options["proxy_port"] or socks.DEFAULT_PORTS[options["socks_version"]]
    addresses = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    for family, kind, protocol, _, address in addresses:
        _remaining(deadline, 5)
        sock = _DeadlineSocksSocket(family, kind, protocol, deadline=deadline)
        try:
            for option in connection.socket_options or ():
                sock.setsockopt(*option)
            sock.set_proxy(
                options["socks_version"], address[0], address[1],
                options["rdns"], options["username"], options["password"],
            )
            if connection.source_address:
                sock.bind(connection.source_address)
            sock.connect((connection.host, connection.port))
            return sock
        except (OSError, socks.ProxyError):
            sock.close()
    raise NewConnectionError(connection, "AWS Bills proxy connection failed") from None


class DeadlineAdapter(HTTPAdapter):
    def __init__(self, deadline):
        self.deadline = deadline
        self._configured_managers = set()
        super().__init__(max_retries=0)

    def _configure_manager(self, manager):
        if manager in self._configured_managers:
            return
        deadline = self.deadline

        class Response(HTTPResponse):
            def __init__(self, sock, *args, **kwargs):
                super().__init__(sock, *args, **kwargs)
                # No reads have occurred yet. Preserve SocketIO's ownership of
                # its file reference, including TLS and Connection: close.
                self.fp = io.BufferedReader(_DeadlineReader(self.fp.detach(), sock, deadline))

        def bounded_pool(pool):
            class Connection(pool.ConnectionCls):
                response_class = Response

                def _new_conn(self):
                    self.timeout = _remaining(deadline, 5)
                    sock = (_proxy_socket(self, deadline) if isinstance(self, SOCKSConnection)
                            else super()._new_conn())
                    try:
                        # TLS handshake uses the remaining budget after TCP /
                        # SOCKS negotiation, not the original connect timeout.
                        sock.settimeout(_remaining(deadline, 5))
                        return sock
                    except OSError:
                        sock.close()
                        raise

            class Pool(pool):
                ConnectionCls = Connection

            return Pool

        # urllib3's default dictionaries are shared between managers. Replace
        # only this manager's map, preserving direct and SOCKS pool behavior.
        manager.pool_classes_by_scheme = {
            scheme: bounded_pool(pool) for scheme, pool in manager.pool_classes_by_scheme.items()
        }
        self._configured_managers.add(manager)

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self._configure_manager(self.poolmanager)

    def proxy_manager_for(self, *args, **kwargs):
        manager = super().proxy_manager_for(*args, **kwargs)
        self._configure_manager(manager)
        return manager
