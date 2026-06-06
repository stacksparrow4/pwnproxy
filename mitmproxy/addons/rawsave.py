import logging
import os
import re
import shutil
import time
from collections.abc import Sequence
from pathlib import Path

from mitmproxy import command
from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.log import ALERT
from mitmproxy.net.http import url
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


class RawSave:
    """
    Persist every HTTP request and response to the current working directory
    as numbered, zero-padded ``000001.req`` / ``.000001.resp`` files.

    Request files are prefixed with a small ``---`` delimited metadata block
    describing the connection (host, port, protocol, sni) followed by the raw
    HTTP request. Response files contain the raw HTTP response and are stored
    as hidden files (with a leading dot) alongside their request counterparts.
    """

    def __init__(self, directory: str = "history") -> None:
        # Files are stored in a "history" folder in the current working
        # directory by default. The folder is created lazily when the first
        # file is written (see _write).
        self.directory = Path(directory)
        # Maps flow.id -> the number assigned to that flow.
        self.flow_numbers: dict[str, int] = {}
        # ids of flows we restored on startup, so we don't immediately
        # re-save them when load_flow replays their lifecycle events.
        self.restored_ids: set[str] = set()
        # Burp-style interactive intercept: when enabled, each request (or
        # response) is opened in Neovim for editing before it is forwarded.
        self.intercept_request: bool = False
        self.intercept_response: bool = False
        # Start after any pre-existing N.req/N.resp files so we never clobber
        # data from a previous run.
        self.counter = self._highest_existing_number()

    def _highest_existing_number(self) -> int:
        highest = 0
        pattern = re.compile(r"^\.?(\d+)\.(req|resp)$")
        try:
            entries = list(self.directory.iterdir())
        except OSError:
            return 0
        for entry in entries:
            m = pattern.match(entry.name)
            if m:
                highest = max(highest, int(m.group(1)))
        return highest

    @staticmethod
    def _name(n: int, suffix: str) -> str:
        """Build a file name, zero-padded to six digits, e.g. ``000001.req``.

        Response files are prefixed with a dot (e.g. ``.000001.resp``) so they
        are hidden files alongside their visible ``.req`` counterparts.
        """
        if suffix == "resp":
            return f".{n:06d}.{suffix}"
        return f"{n:06d}.{suffix}"

    def _number_for(self, flow: http.HTTPFlow) -> int:
        n = self.flow_numbers.get(flow.id)
        if n is None:
            self.counter += 1
            n = self.counter
            self.flow_numbers[flow.id] = n
        return n

    def _write(self, name: str, data: bytes) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
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

    def _link_into_map(self, flow: http.HTTPFlow, name: str) -> None:
        """
        Create a symlink for ``history/<name>`` under a ``map`` directory whose
        subdirectory structure mirrors the request's host and path, e.g.
        a request to https://example.com/test saved as history/000001.req gets
        a symlink at map/example.com/test/000001.req -> ../../../history/000001.req.

        Query strings are ignored; each path segment becomes a directory.
        """
        request = flow.request
        parts = [request.host, *request.path_components]
        # Skip empty/traversal segments so a hostile target can't escape map/.
        safe = [
            p.replace("/", "_").replace(os.sep, "_")
            for p in parts
            if p and p not in (".", "..")
        ]
        map_dir = self.directory.parent / "map"
        subdir = map_dir.joinpath(*safe)
        link = subdir / name
        target = os.path.relpath(self.directory / name, subdir)
        try:
            subdir.mkdir(parents=True, exist_ok=True)
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(target)
        except OSError as e:
            logger.error(f"Error while creating map symlink {link}: {e}")

    def save_request(self, flow: http.HTTPFlow) -> None:
        n = self._number_for(flow)
        head = self._assemble_request_head(flow.request)
        body = flow.request.data.content or b""
        raw = head + body
        # Use bare \n line endings (technically not valid HTTP) as requested.
        raw = raw.replace(b"\r\n", b"\n")
        name = self._name(n, "req")
        self._write(name, self._metadata(flow) + raw)
        self._link_into_map(flow, name)

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
        name = self._name(n, "resp")
        self._write(name, raw)
        self._link_into_map(flow, name)

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

    def _parse_request_file(self, req_bytes: bytes) -> tuple[http.Request, str | None]:
        """Parse a saved ``.req`` file into a Request and its SNI."""
        # A valid request file has a leading ``---``-delimited metadata block;
        # if it's missing this unpack raises ValueError, which callers handle.
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
        return request, sni

    def _parse_response_file(self, resp_bytes: bytes) -> http.Response:
        """Parse a saved ``.resp`` file into a Response."""
        head_lines, body = self._parse_head_and_body(resp_bytes)
        status_line = head_lines[0].split(b" ")
        now = time.time()
        return http.Response(
            http_version=status_line[0],
            status_code=int(status_line[1]),
            reason=b" ".join(status_line[2:]),
            headers=self._parse_headers(head_lines[1:]),
            content=body,
            trailers=None,
            timestamp_start=now,
            timestamp_end=now,
        )

    def _build_flow(self, req_bytes: bytes, resp_bytes: bytes | None) -> http.HTTPFlow:
        request, sni = self._parse_request_file(req_bytes)
        now = time.time()
        client = connection.Client(
            peername=("0.0.0.0", 0), sockname=("0.0.0.0", 0), timestamp_start=now
        )
        server = connection.Server(address=(request.host, request.port))
        server.sni = sni
        flow = http.HTTPFlow(client, server)
        flow.request = request
        if resp_bytes is not None:
            flow.response = self._parse_response_file(resp_bytes)
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
            req_file = self.directory / self._name(n, "req")
            resp_file = self.directory / self._name(n, "resp")
            try:
                req_bytes = req_file.read_bytes()
                resp_bytes = resp_file.read_bytes() if resp_file.exists() else None
                flow = self._build_flow(req_bytes, resp_bytes)
            except (OSError, ValueError, IndexError) as e:
                logger.warning(f"Could not restore {self._name(n, 'req')}: {e}")
                continue
            self.restored_ids.add(flow.id)
            self.flow_numbers[flow.id] = n
            flows.append(flow)
        return flows

    @command.command("rawsave.replay")
    def replay(self, flows: Sequence[flow.Flow]) -> None:
        """
        Copy the saved ``.req``/``.resp`` files for the given flows into a
        "replay" directory, preserving their numbers (e.g. history/000001.req
        -> replay/000001.req). The replay directory is created if needed.
        """
        replay_dir = Path("replay")
        for f in flows:
            n = self.flow_numbers.get(f.id)
            if n is None:
                logger.warning("No saved request file for this flow.")
                continue
            try:
                replay_dir.mkdir(parents=True, exist_ok=True)
                for suffix in ("req", "resp"):
                    name = self._name(n, suffix)
                    src = self.directory / name
                    if src.exists():
                        shutil.copyfile(src, replay_dir / name)
            except OSError as e:
                logger.error(f"Error while copying to {replay_dir}: {e}")
                continue
            logging.log(ALERT, str(replay_dir / self._name(n, "req")))

    def req_path(self, flow: http.HTTPFlow) -> Path | None:
        """Return the path of the ``.req`` file for ``flow``, if it exists."""
        n = self.flow_numbers.get(flow.id)
        if n is None:
            return None
        path = self.directory / self._name(n, "req")
        if not path.exists():
            return None
        return path

    # Burp-style interactive intercept

    @command.command("rawsave.intercept.toggle")
    def intercept_toggle(self) -> None:
        """Toggle interactive request intercept (edit each request in Neovim)."""
        self.intercept_request = not self.intercept_request
        state = "on" if self.intercept_request else "off"
        logging.log(ALERT, f"Request intercept: {state}")

    @command.command("rawsave.intercept.response.toggle")
    def intercept_response_toggle(self) -> None:
        """Toggle interactive response intercept (edit each response in Neovim)."""
        self.intercept_response = not self.intercept_response
        state = "on" if self.intercept_response else "off"
        logging.log(ALERT, f"Response intercept: {state}")

    # Special intercept-only keys and their defaults. These are injected into
    # the ``---`` block of the file opened in Neovim, but are never written to
    # the on-disk .req/.resp/.orig files.
    _INTERCEPT_KEYS: dict[str, bool] = {
        "stop_intercepting": False,
        "update_content_length": True,
    }

    def _inject_intercept_keys(self, content: bytes, has_metadata: bool) -> bytes:
        block = "".join(
            f"{k}: {str(v).lower()}\n" for k, v in self._INTERCEPT_KEYS.items()
        ).encode()
        if has_metadata:
            # Requests already start with a "---" block; insert the keys into it.
            _, rest = content.split(b"---\n", 1)
            return b"---\n" + block + rest
        # Responses have no "---" block on disk; add a temporary one.
        return b"---\n" + block + b"---\n" + content

    def _extract_intercept_keys(
        self, content: bytes, has_metadata: bool
    ) -> tuple[dict[str, bool], bytes]:
        opts = dict(self._INTERCEPT_KEYS)
        if not content.startswith(b"---\n"):
            return opts, content
        _, block, rest = content.split(b"---\n", 2)
        kept = []
        for line in block.splitlines():
            key, sep, value = line.partition(b":")
            name = key.strip().decode()
            if name in self._INTERCEPT_KEYS:
                opts[name] = value.strip().lower() == b"true"
            else:
                kept.append(line)
        if has_metadata:
            kept_block = b"\n".join(kept)
            cleaned = (
                b"---\n" + (kept_block + b"\n" if kept_block else b"") + b"---\n" + rest
            )
        else:
            cleaned = rest
        return opts, cleaned

    @staticmethod
    def _fix_content_length(content: bytes) -> bytes:
        """Replace an existing Content-Length header with the actual body size."""
        head, sep, body = content.partition(b"\n\n")
        if not sep:
            return content
        lines = head.split(b"\n")
        changed = False
        for i, line in enumerate(lines):
            key, colon, _ = line.partition(b":")
            if colon and key.strip().lower() == b"content-length":
                lines[i] = key + b": " + str(len(body)).encode()
                changed = True
        if not changed:
            return content
        return b"\n".join(lines) + b"\n\n" + body

    def _run_intercept(
        self, path: Path, has_metadata: bool
    ) -> tuple[str, bytes | None] | None:
        """
        Open ``path`` in Neovim with the special intercept keys injected.

        Returns one of:
          * None - editing was unavailable or failed; do nothing.
          * ("stop", None) - the user requested ``stop_intercepting``; edits are
            discarded and the original file is restored.
          * ("apply", cleaned) - the cleaned (keys-stripped) edited bytes, which
            have been written to ``path`` (and the original to ``<path>.orig``
            if it changed).
        """
        editor = getattr(ctx.master, "spawn_editor_file", None)
        if editor is None:
            logger.warning("Interactive intercept requires the console interface.")
            return None
        try:
            original = path.read_bytes()
            path.write_bytes(self._inject_intercept_keys(original, has_metadata))
            editor(str(path))
            edited = path.read_bytes()
            opts, cleaned = self._extract_intercept_keys(edited, has_metadata)
            if opts["stop_intercepting"]:
                path.write_bytes(original)  # discard edits
                return "stop", None
            if opts["update_content_length"]:
                cleaned = self._fix_content_length(cleaned)
            path.write_bytes(cleaned)
            if cleaned != original:
                path.with_name(path.name + ".orig").write_bytes(original)
            return "apply", cleaned
        except OSError as e:
            logger.error(f"Error while editing {path}: {e}")
            return None

    def _intercept_request(self, flow: http.HTTPFlow) -> None:
        path = self.req_path(flow)
        if path is None:
            return
        result = self._run_intercept(path, has_metadata=True)
        if result is None:
            return
        action, cleaned = result
        if action == "stop":
            self.intercept_request = False
            logging.log(ALERT, "Request intercept: off")
            return
        assert cleaned is not None
        try:
            request, _ = self._parse_request_file(cleaned)
        except (ValueError, IndexError) as e:
            logger.error(f"Could not parse edited request: {e}")
            return
        flow.request = request

    def _intercept_response(self, flow: http.HTTPFlow) -> None:
        n = self.flow_numbers.get(flow.id)
        if n is None:
            return
        path = self.directory / self._name(n, "resp")
        if not path.exists():
            return
        result = self._run_intercept(path, has_metadata=False)
        if result is None:
            return
        action, cleaned = result
        if action == "stop":
            self.intercept_response = False
            logging.log(ALERT, "Response intercept: off")
            return
        assert cleaned is not None
        try:
            flow.response = self._parse_response_file(cleaned)
        except (ValueError, IndexError) as e:
            logger.error(f"Could not parse edited response: {e}")
            return

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
        if self.intercept_request:
            self._intercept_request(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.id in self.restored_ids:
            return
        self.save_response(flow)
        if self.intercept_response:
            self._intercept_response(flow)
