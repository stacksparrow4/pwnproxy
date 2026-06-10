import socket
import struct
import time
from enum import auto
from enum import Enum
from logging import DEBUG

from h11._receivebuffer import ReceiveBuffer

from mitmproxy import connection
from mitmproxy import http
from mitmproxy.net.http import http1
from mitmproxy.proxy import commands
from mitmproxy.proxy import context
from mitmproxy.proxy import layer
from mitmproxy.proxy import tunnel
from mitmproxy.proxy.layers import tls
from mitmproxy.proxy.layers.http._hooks import HttpConnectUpstreamHook
from mitmproxy.utils import human


class HttpUpstreamProxy(tunnel.TunnelLayer):
    buf: ReceiveBuffer
    send_connect: bool
    conn: connection.Server
    tunnel_connection: connection.Server

    def __init__(
        self, ctx: context.Context, tunnel_conn: connection.Server, send_connect: bool
    ):
        super().__init__(ctx, tunnel_connection=tunnel_conn, conn=ctx.server)
        self.buf = ReceiveBuffer()
        self.send_connect = send_connect

    @classmethod
    def make(cls, ctx: context.Context, send_connect: bool) -> tunnel.LayerStack:
        assert ctx.server.via
        scheme, address = ctx.server.via
        assert scheme in ("http", "https")

        http_proxy = connection.Server(address=address)

        stack = tunnel.LayerStack()
        if scheme == "https":
            http_proxy.alpn_offers = tls.HTTP1_ALPNS
            http_proxy.sni = address[0]
            stack /= tls.ServerTLSLayer(ctx, http_proxy)
        stack /= cls(ctx, http_proxy, send_connect)

        return stack

    def start_handshake(self) -> layer.CommandGenerator[None]:
        if not self.send_connect:
            return (yield from super().start_handshake())
        assert self.conn.address
        flow = http.HTTPFlow(self.context.client, self.tunnel_connection)
        authority = (
            self.conn.address[0].encode("idna") + f":{self.conn.address[1]}".encode()
        )
        headers = http.Headers()
        if self.context.options.http_connect_send_host_header:
            headers.insert(0, b"Host", authority)
        flow.request = http.Request(
            host=self.conn.address[0],
            port=self.conn.address[1],
            method=b"CONNECT",
            scheme=b"",
            authority=authority,
            path=b"",
            http_version=b"HTTP/1.1",
            headers=headers,
            content=b"",
            trailers=None,
            timestamp_start=time.time(),
            timestamp_end=time.time(),
        )
        yield HttpConnectUpstreamHook(flow)
        raw = http1.assemble_request(flow.request)
        yield commands.SendData(self.tunnel_connection, raw)

    def receive_handshake_data(
        self, data: bytes
    ) -> layer.CommandGenerator[tuple[bool, str | None]]:
        if not self.send_connect:
            return (yield from super().receive_handshake_data(data))
        self.buf += data
        response_head = self.buf.maybe_extract_lines()
        if response_head:
            try:
                response = http1.read_response_head([bytes(x) for x in response_head])
            except ValueError as e:
                proxyaddr = human.format_address(self.tunnel_connection.address)
                yield commands.Log(f"{proxyaddr}: {e}")
                return False, f"Error connecting to {proxyaddr}: {e}"
            if 200 <= response.status_code < 300:
                if self.buf:
                    yield from self.receive_data(bytes(self.buf))
                    del self.buf
                return True, None
            else:
                proxyaddr = human.format_address(self.tunnel_connection.address)
                raw_resp = b"\n".join(response_head)
                yield commands.Log(f"{proxyaddr}: {raw_resp!r}", DEBUG)
                return (
                    False,
                    f"Upstream proxy {proxyaddr} refused HTTP CONNECT request: {response.status_code} {response.reason}",
                )
        else:
            return False, None


SOCKS5_VERSION = 0x05

SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED = 0x00
SOCKS5_METHOD_USER_PASSWORD_AUTHENTICATION = 0x02

SOCKS5_AUTH_VERSION = 0x01

SOCKS5_CMD_CONNECT = 0x01

SOCKS5_ATYP_IPV4_ADDRESS = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03
SOCKS5_ATYP_IPV6_ADDRESS = 0x04

SOCKS5_REP_SUCCEEDED = 0x00
SOCKS5_REP_MESSAGES = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class Socks5HandshakeState(Enum):
    GREETING = auto()
    AUTHENTICATING = auto()
    CONNECTING = auto()


class Socks5UpstreamProxy(tunnel.TunnelLayer):
    """Forward all connections to an upstream SOCKS5 proxy."""

    buf: bytes
    state: Socks5HandshakeState
    conn: connection.Server
    tunnel_connection: connection.Server

    def __init__(self, ctx: context.Context, tunnel_conn: connection.Server) -> None:
        super().__init__(ctx, tunnel_connection=tunnel_conn, conn=ctx.server)
        self.buf = b""
        self.state = Socks5HandshakeState.GREETING

    @classmethod
    def make(cls, ctx: context.Context) -> tunnel.LayerStack:
        assert ctx.server.via
        scheme, address = ctx.server.via
        assert scheme == "socks5"

        socks_proxy = connection.Server(address=address)

        stack = tunnel.LayerStack()
        stack /= cls(ctx, socks_proxy)

        return stack

    def _credentials(self) -> tuple[str, str] | None:
        if (
            "upstream_auth" in self.context.options
            and self.context.options.upstream_auth
        ):
            user, _, password = self.context.options.upstream_auth.partition(":")
            return user, password
        return None

    def start_handshake(self) -> layer.CommandGenerator[None]:
        if self._credentials() is not None:
            methods = bytes(
                [
                    SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED,
                    SOCKS5_METHOD_USER_PASSWORD_AUTHENTICATION,
                ]
            )
        else:
            methods = bytes([SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED])
        greeting = bytes([SOCKS5_VERSION, len(methods)]) + methods
        yield commands.SendData(self.tunnel_connection, greeting)

    def _send_connect_request(self) -> layer.CommandGenerator[None]:
        assert self.conn.address
        host, port = self.conn.address
        try:
            addr = socket.inet_pton(socket.AF_INET, host)
            atyp = SOCKS5_ATYP_IPV4_ADDRESS
        except OSError:
            try:
                addr = socket.inet_pton(socket.AF_INET6, host)
                atyp = SOCKS5_ATYP_IPV6_ADDRESS
            except OSError:
                host_bytes = host.encode("idna")
                addr = bytes([len(host_bytes)]) + host_bytes
                atyp = SOCKS5_ATYP_DOMAINNAME
        request = (
            bytes([SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, atyp])
            + addr
            + struct.pack("!H", port)
        )
        yield commands.SendData(self.tunnel_connection, request)
        self.state = Socks5HandshakeState.CONNECTING

    def receive_handshake_data(
        self, data: bytes
    ) -> layer.CommandGenerator[tuple[bool, str | None]]:
        self.buf += data
        proxyaddr = human.format_address(self.tunnel_connection.address)

        if self.state is Socks5HandshakeState.GREETING:
            if len(self.buf) < 2:
                return False, None
            version, method = self.buf[0], self.buf[1]
            self.buf = self.buf[2:]
            if version != SOCKS5_VERSION:
                return (
                    False,
                    f"Invalid SOCKS version from upstream proxy {proxyaddr}. "
                    f"Expected 0x05, got 0x{version:02x}.",
                )
            credentials = self._credentials()
            if method == SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED:
                yield from self._send_connect_request()
            elif (
                method == SOCKS5_METHOD_USER_PASSWORD_AUTHENTICATION
                and credentials is not None
            ):
                user, password = credentials
                user_bytes = user.encode()
                pass_bytes = password.encode()
                auth = (
                    bytes([SOCKS5_AUTH_VERSION, len(user_bytes)])
                    + user_bytes
                    + bytes([len(pass_bytes)])
                    + pass_bytes
                )
                yield commands.SendData(self.tunnel_connection, auth)
                self.state = Socks5HandshakeState.AUTHENTICATING
            else:
                return (
                    False,
                    f"Upstream SOCKS5 proxy {proxyaddr} did not accept an "
                    f"authentication method we support.",
                )

        if self.state is Socks5HandshakeState.AUTHENTICATING:
            if len(self.buf) < 2:
                return False, None
            version, status = self.buf[0], self.buf[1]
            self.buf = self.buf[2:]
            if version != SOCKS5_AUTH_VERSION or status != 0x00:
                return (
                    False,
                    f"Upstream SOCKS5 proxy {proxyaddr} refused authentication.",
                )
            yield from self._send_connect_request()

        if self.state is Socks5HandshakeState.CONNECTING:
            if len(self.buf) < 4:
                return False, None
            version, reply, _, atyp = self.buf[0], self.buf[1], self.buf[2], self.buf[3]
            if atyp == SOCKS5_ATYP_IPV4_ADDRESS:
                message_len = 4 + 4 + 2
            elif atyp == SOCKS5_ATYP_IPV6_ADDRESS:
                message_len = 4 + 16 + 2
            elif atyp == SOCKS5_ATYP_DOMAINNAME:
                if len(self.buf) < 5:
                    return False, None
                message_len = 4 + 1 + self.buf[4] + 2
            else:
                return (
                    False,
                    f"Upstream SOCKS5 proxy {proxyaddr} returned unknown "
                    f"address type {atyp}.",
                )
            if len(self.buf) < message_len:
                return False, None
            self.buf = self.buf[message_len:]
            if reply != SOCKS5_REP_SUCCEEDED:
                reason = SOCKS5_REP_MESSAGES.get(reply, f"unknown error 0x{reply:02x}")
                return (
                    False,
                    f"Upstream SOCKS5 proxy {proxyaddr} refused connection: {reason}.",
                )
            if self.buf:
                yield from self.receive_data(self.buf)
                self.buf = b""
            return True, None

        raise AssertionError(self.state)  # pragma: no cover
