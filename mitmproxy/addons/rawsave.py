import logging
import re
import time
from pathlib import Path

from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.net.http import url
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


class RawSave:
    """
    Persist every HTTP request and response to the current working directory
    as numbered ``N.req`` / ``N.resp`` files.

    Request files are prefixed with a small ``---`` delimited metadata block
    describing the connection (host, port, protocol, sni) followed by the raw
    HTTP request. Response files contain the raw HTTP response.
    """

    def __init__(self, directory: str = ".") -> None:
        self.directory = Path(directory)
        # Maps flow.id -> the number assigned to that flow.
        self.flow_numbers: dict[str, int] = {}
        # ids of flows we restored on startup, so we don't immediately
        # re-save them when load_flow replays their lifecycle events.
        self.restored_ids: set[str] = set()
        # Start after any pre-existing N.req/N.resp files so we never clobber
        # data from a previous run.
        self.counter = self._highest_existing_number()

    def _highest_existing_number(self) -> int:
        highest = 0
        pattern = re.compile(r"^(\d+)\.(req|resp)$")
        try:
            entries = list(self.directory.iterdir())
        except OSError:
            return 0
        for entry in entries:
            m = pattern.match(entry.name)
            if m:
                highest = max(highest, int(m.group(1)))
        return highest

    def _number_for(self, flow: http.HTTPFlow) -> int:
        n = self.flow_numbers.get(flow.id)
        if n is None:
            self.counter += 1
            n = self.counter
            self.flow_numbers[flow.id] = n
        return n

    def _write(self, name: str, data: bytes) -> None:
        try:
            (self.directory / name).write_bytes(data)
        except OSError as e:
            logger.error(f"Error while writing {name}: {e}")

    def _metadata(self, flow: http.HTTPFlow) -> bytes:
        request = flow.request
        protocol = request.scheme or ("https" if request.port == 443 else "http")
        sni = flow.server_conn.sni or flow.client_conn.sni or ""

        # The host portion of the Host/authority header, used to determine
        # whether host/sni match their defaults.
        header_host = None
        if request.host_header:
            header_host, _ = url.parse_authority(request.host_header, check=False)

        default_port = 443 if protocol == "https" else 80

        lines = ["---"]
        if request.host != header_host:
            lines.append(f"host: {request.host}")
        if request.port != default_port:
            lines.append(f"port: {request.port}")
        lines.append(f"protocol: {protocol}")
        if sni and sni != header_host:
            lines.append(f"sni: {sni}")
        lines.append("---")

        meta = "".join(f"{line}\n" for line in lines)
        return meta.encode("utf-8", "surrogateescape")

    def _assemble_request_head(self, request: http.Request) -> bytes:
        """
        Assemble the request head as it was intercepted (origin-form), rather
        than the proxy/absolute-form that http1 assembly emits when an
        authority is present (e.g. for HTTP/2 and HTTP/3 requests).
        """
        data = request.data
        if request.first_line_format == "authority":
            # CONNECT requests legitimately use authority-form.
            first_line = b"%s %s %s" % (data.method, data.authority, data.http_version)
            headers = request.headers
        else:
            first_line = b"%s %s %s" % (data.method, data.path, data.http_version)
            headers = request.headers
            if "host" not in headers and request.host_header:
                # HTTP/2 and HTTP/3 carry the authority out-of-band; restore it
                # as a Host header so the saved request looks like HTTP/1.x.
                headers = http.Headers(headers.fields)
                headers.insert(0, "Host", request.host_header)
        return b"%s\r\n%s\r\n" % (first_line, bytes(headers))

    def save_request(self, flow: http.HTTPFlow) -> None:
        n = self._number_for(flow)
        head = self._assemble_request_head(flow.request)
        body = flow.request.data.content or b""
        raw = head + body
        # Use bare \n line endings (technically not valid HTTP) as requested.
        raw = raw.replace(b"\r\n", b"\n")
        self._write(f"{n}.req", self._metadata(flow) + raw)

    def _assemble_response(self, response: http.Response) -> bytes:
        """
        Assemble the response with a decoded (e.g. un-gzipped/un-brotli'd) body.

        Works on a copy of the headers so the live flow is left untouched.
        """
        body = response.get_content(strict=False) or b""
        headers = http.Headers(response.headers.fields)
        # The body is no longer compressed or chunked, so drop the encodings
        # and make content-length match the decoded body.
        if "content-encoding" in headers:
            del headers["content-encoding"]
        if "transfer-encoding" in headers:
            del headers["transfer-encoding"]
        headers["content-length"] = str(len(body))
        first_line = b"%s %d %s" % (
            response.data.http_version,
            response.data.status_code,
            response.data.reason,
        )
        head = b"%s\r\n%s\r\n" % (first_line, bytes(headers))
        # Use bare \n line endings in the head (matching the request files).
        # The body is left untouched as it may be binary.
        head = head.replace(b"\r\n", b"\n")
        return head + body

    def save_response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        n = self._number_for(flow)
        raw = self._assemble_response(flow.response)
        self._write(f"{n}.resp", raw)

    # Restoring previously saved flows

    @staticmethod
    def _parse_head_and_body(raw: bytes) -> tuple[list[bytes], bytes]:
        """Split a saved message into its head lines and body."""
        head, _, body = raw.partition(b"\n\n")
        return head.split(b"\n"), body

    @staticmethod
    def _parse_headers(header_lines: list[bytes]) -> http.Headers:
        fields = []
        for line in header_lines:
            if not line:
                continue
            key, _, value = line.partition(b":")
            fields.append((key.strip(), value.strip()))
        return http.Headers(fields)

    def _build_flow(self, req_bytes: bytes, resp_bytes: bytes | None) -> http.HTTPFlow:
        # A valid request file has a leading ``---``-delimited metadata block;
        # if it's missing this unpack raises ValueError, which the caller skips.
        _, meta_block, rest = req_bytes.split(b"---\n", 2)

        meta: dict[str, str] = {}
        for line in meta_block.splitlines():
            key, sep, value = line.partition(b":")
            if sep:
                meta[key.strip().decode()] = value.strip().decode()

        head_lines, body = self._parse_head_and_body(rest)
        request_line = head_lines[0].split(b" ")
        method = request_line[0]
        http_version = request_line[-1]
        target = b" ".join(request_line[1:-1])
        headers = self._parse_headers(head_lines[1:])

        protocol = meta.get("protocol", "http")
        default_port = 443 if protocol == "https" else 80
        port = int(meta["port"]) if "port" in meta else default_port

        header_host = None
        host_header = headers.get("host")
        if host_header:
            header_host, _ = url.parse_authority(host_header, check=False)
        host = meta.get("host") or header_host or ""
        sni = meta.get("sni") or (host if protocol == "https" else None)

        if method.upper() == b"CONNECT":
            authority = target
            path = b""
        else:
            authority = b""
            path = target

        now = time.time()
        request = http.Request(
            host=host,
            port=port,
            method=method,
            scheme=protocol.encode(),
            authority=authority,
            path=path,
            http_version=http_version,
            headers=headers,
            content=body,
            trailers=None,
            timestamp_start=now,
            timestamp_end=now,
        )

        client = connection.Client(
            peername=("0.0.0.0", 0), sockname=("0.0.0.0", 0), timestamp_start=now
        )
        server = connection.Server(address=(host, port))
        server.sni = sni
        flow = http.HTTPFlow(client, server)
        flow.request = request

        if resp_bytes is not None:
            resp_head_lines, resp_body = self._parse_head_and_body(resp_bytes)
            status_line = resp_head_lines[0].split(b" ")
            flow.response = http.Response(
                http_version=status_line[0],
                status_code=int(status_line[1]),
                reason=b" ".join(status_line[2:]),
                headers=self._parse_headers(resp_head_lines[1:]),
                content=resp_body,
                trailers=None,
                timestamp_start=now,
                timestamp_end=now,
            )

        return flow

    def _restored_flows(self) -> list[http.HTTPFlow]:
        pattern = re.compile(r"^(\d+)\.req$")
        numbers = []
        try:
            entries = list(self.directory.iterdir())
        except OSError:
            return []
        for entry in entries:
            m = pattern.match(entry.name)
            if m:
                numbers.append(int(m.group(1)))

        flows = []
        for n in sorted(numbers):
            req_file = self.directory / f"{n}.req"
            resp_file = self.directory / f"{n}.resp"
            try:
                req_bytes = req_file.read_bytes()
                resp_bytes = resp_file.read_bytes() if resp_file.exists() else None
                flow = self._build_flow(req_bytes, resp_bytes)
            except (OSError, ValueError, IndexError) as e:
                logger.warning(f"Could not restore {n}.req: {e}")
                continue
            self.restored_ids.add(flow.id)
            self.flow_numbers[flow.id] = n
            flows.append(flow)
        return flows

    def req_path(self, flow: http.HTTPFlow) -> Path | None:
        """Return the path of the ``.req`` file for ``flow``, if it exists."""
        n = self.flow_numbers.get(flow.id)
        if n is None:
            return None
        path = self.directory / f"{n}.req"
        if not path.exists():
            return None
        return path

    async def restore(self) -> None:
        for flow in self._restored_flows():
            await ctx.master.load_flow(flow)

    # mitmproxy hooks

    def running(self) -> None:
        asyncio_utils.create_task(
            self.restore(), name="rawsave restore", keep_ref=False
        )

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.id in self.restored_ids:
            return
        self.save_request(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.id in self.restored_ids:
            return
        self.save_response(flow)
