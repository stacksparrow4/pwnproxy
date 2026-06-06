import logging
import re
from pathlib import Path

from mitmproxy import http
from mitmproxy.net.http import url

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
        return b"%s\r\n%s\r\n%s" % (first_line, bytes(headers), body)

    def save_response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        n = self._number_for(flow)
        raw = self._assemble_response(flow.response)
        self._write(f"{n}.resp", raw)

    # mitmproxy hooks

    def request(self, flow: http.HTTPFlow) -> None:
        self.save_request(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        self.save_response(flow)
