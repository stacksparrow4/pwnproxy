import logging
import os
import re
import shutil
import time
from collections.abc import Sequence
from pathlib import Path

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.log import ALERT
from mitmproxy.net.http import url

logger = logging.getLogger(__name__)

# Width (in digits) that flow numbers are zero-padded to, e.g. ``000001``.
# Shared with the console UI (flow list column) so the on-disk file names and
# the displayed request id stay in sync.
NUMBER_WIDTH = 6


class RawSave:
    """
    Persist every HTTP request and response to the current working directory
    as numbered, zero-padded ``000001.req`` / ``000001.req.resp`` files.

    Request files are prefixed with a small ``---`` delimited metadata block
    describing the connection (host, port, protocol, sni) followed by the raw
    HTTP request. Response files contain the raw HTTP response and are stored
    alongside their request counterparts with an additional ``.resp`` suffix.
    """

    def __init__(self, directory: str = "history") -> None:
        # Files are stored in a "history" folder in the current working
        # directory by default. The folder is created lazily when the first
        # file is written (see _write).
        self.directory = Path(directory)
        # Maps flow.id -> the number assigned to that flow.
        self.flow_numbers: dict[str, int] = {}
        # Burp-style interactive intercept: when enabled, each request (or
        # response) is opened in an external editor for editing before it is
        # forwarded.
        self.intercept_request: bool = False
        self.intercept_response: bool = False
        # Start after any pre-existing N.req/N.req.resp files so we never
        # clobber data from a previous run.
        self.counter = self._highest_existing_number()

    def _highest_existing_number(self) -> int:
        highest = 0
        pattern = re.compile(r"^(\d+)\.req(\.resp)?$")
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
    def _file_name(base: str, suffix: str) -> str:
        """Build a file name from a ``base`` and a ``req``/``resp`` suffix.

        Response files share the request file name with an additional ``.resp``
        suffix (e.g. ``000001.req`` -> ``000001.req.resp``).
        """
        if suffix == "resp":
            return f"{base}.req.resp"
        return f"{base}.{suffix}"

    @classmethod
    def _name(cls, n: int, suffix: str) -> str:
        """File name for flow number ``n``, zero-padded (e.g. ``000001.req``)."""
        return cls._file_name(f"{n:0{NUMBER_WIDTH}d}", suffix)

    @staticmethod
    def _serialize_block(meta: dict[str, str]) -> bytes:
        """Serialize a metadata mapping into a ``---``-delimited block."""
        lines = ["---", *(f"{k}: {v}" for k, v in meta.items()), "---"]
        text = "".join(f"{line}\n" for line in lines)
        return text.encode("utf-8", "surrogateescape")

    @staticmethod
    def _parse_block(raw: bytes) -> tuple[dict[str, str], bytes]:
        """Split a leading ``---``-delimited block from ``raw``.

        Returns the parsed ``key: value`` pairs and the bytes following the
        block. If ``raw`` does not start with a ``---`` block, an empty mapping
        and the original bytes are returned.
        """
        if not raw.startswith(b"---\n"):
            return {}, raw
        _, block, rest = raw.split(b"---\n", 2)
        meta: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition(b":")
            if sep:
                meta[key.strip().decode()] = value.strip().decode()
        return meta, rest

    def _number_for(self, f: http.HTTPFlow) -> int:
        n = self.flow_numbers.get(f.id)
        if n is None:
            self.counter += 1
            n = self.counter
            self.flow_numbers[f.id] = n
        return n

    def _write(self, name: str, data: bytes) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            (self.directory / name).write_bytes(data)
        except OSError as e:
            logger.error(f"Error while writing {name}: {e}")

    def _metadata(self, f: http.HTTPFlow) -> bytes:
        request = f.request
        protocol = request.scheme or ("https" if request.port == 443 else "http")
        sni = f.server_conn.sni or f.client_conn.sni or ""

        # The host portion of the Host/authority header, used to determine
        # whether host/sni match their defaults.
        header_host = None
        if request.host_header:
            header_host, _ = url.parse_authority(request.host_header, check=False)

        default_port = 443 if protocol == "https" else 80

        # Only non-default fields are written; order is significant for the
        # on-disk format (host, port, protocol, sni).
        meta: dict[str, str] = {}
        if request.host != header_host:
            meta["host"] = request.host
        if request.port != default_port:
            meta["port"] = str(request.port)
        meta["protocol"] = protocol
        if sni and sni != header_host:
            meta["sni"] = sni
        return self._serialize_block(meta)

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

    def _link_into_map(self, f: http.HTTPFlow, name: str) -> None:
        """
        Create a symlink for ``history/<name>`` under a ``map`` directory whose
        subdirectory structure mirrors the request's host and path, e.g.
        a request to https://example.com/test saved as history/000001.req gets
        a symlink at map/example.com/test/000001.req -> ../../../history/000001.req.

        Query strings are ignored; each path segment becomes a directory.
        """
        request = f.request
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

    def save_request(self, f: http.HTTPFlow) -> None:
        n = self._number_for(f)
        head = self._assemble_request_head(f.request)
        body = f.request.data.content or b""
        raw = head + body
        # Use bare \n line endings (technically not valid HTTP) as requested.
        raw = raw.replace(b"\r\n", b"\n")
        name = self._name(n, "req")
        self._write(name, self._metadata(f) + raw)
        self._link_into_map(f, name)

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

    def save_response(self, f: http.HTTPFlow) -> None:
        if f.response is None:
            return
        n = self._number_for(f)
        raw = self._assemble_response(f.response)
        name = self._name(n, "resp")
        self._write(name, raw)
        self._link_into_map(f, name)

    # Parsing saved messages (used by interactive intercept)

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
        # if it's missing we raise ValueError, which callers handle.
        if not req_bytes.startswith(b"---\n"):
            raise ValueError("missing metadata block")
        meta, rest = self._parse_block(req_bytes)

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

    @command.command("rawsave.replay")
    def replay(self, flows: Sequence[flow.Flow], name: str = "") -> None:
        """
        Copy the saved ``.req``/``.resp`` files for the given flows into a
        "replay" directory.

        By default the files keep their numbers (e.g. history/000001.req ->
        replay/000001.req). If ``name`` is given, the files are saved as
        ``replay/<name>.req`` and ``replay/<name>.req.resp`` instead. The replay
        directory is created if needed.
        """
        replay_dir = Path("replay")
        for f in flows:
            n = self.flow_numbers.get(f.id)
            if n is None:
                logger.warning("No saved request file for this flow.")
                continue
            # When a name is given the files are renamed (e.g. <name>.req);
            # otherwise they keep their zero-padded number.
            base = name or f"{n:0{NUMBER_WIDTH}d}"
            try:
                replay_dir.mkdir(parents=True, exist_ok=True)
                for suffix in ("req", "resp"):
                    src = self.directory / self._name(n, suffix)
                    if src.exists():
                        dst = replay_dir / self._file_name(base, suffix)
                        shutil.copyfile(src, dst)
            except OSError as e:
                logger.error(f"Error while copying to {replay_dir}: {e}")
                continue
            logging.log(ALERT, str(replay_dir / self._file_name(base, "req")))

    def _path_for(self, f: http.HTTPFlow, suffix: str) -> Path | None:
        """Return the path of the saved ``suffix`` file for ``f``, if it exists."""
        n = self.flow_numbers.get(f.id)
        if n is None:
            return None
        path = self.directory / self._name(n, suffix)
        if not path.exists():
            return None
        return path

    def req_path(self, f: http.HTTPFlow) -> Path | None:
        """Return the path of the ``.req`` file for ``f``, if it exists."""
        return self._path_for(f, "req")

    def resp_path(self, f: http.HTTPFlow) -> Path | None:
        """Return the path of the ``.resp`` file for ``f``, if it exists."""
        return self._path_for(f, "resp")

    # Burp-style interactive intercept

    @command.command("rawsave.intercept.toggle")
    def intercept_toggle(self) -> None:
        """Toggle interactive request intercept (edit each request in an external editor)."""
        self.intercept_request = not self.intercept_request
        state = "on" if self.intercept_request else "off"
        logging.log(ALERT, f"Request intercept: {state}")

    @command.command("rawsave.intercept.response.toggle")
    def intercept_response_toggle(self) -> None:
        """Toggle interactive response intercept (edit each response in an external editor)."""
        self.intercept_response = not self.intercept_response
        state = "on" if self.intercept_response else "off"
        logging.log(ALERT, f"Response intercept: {state}")

    # Special intercept-only keys and their defaults. These are injected into
    # the ``---`` block of the file opened in the editor, but are never written to
    # the on-disk .req/.resp/.orig files.
    _INTERCEPT_KEYS: dict[str, bool] = {
        "stop_intercepting": False,
        "update_content_length": True,
    }

    def _inject_intercept_keys(self, content: bytes, has_metadata: bool) -> bytes:
        intercept = {k: str(v).lower() for k, v in self._INTERCEPT_KEYS.items()}
        if has_metadata:
            # Requests already start with a "---" block; merge the keys into it,
            # listing the intercept keys first.
            meta, rest = self._parse_block(content)
            return self._serialize_block({**intercept, **meta}) + rest
        # Responses have no "---" block on disk; add a temporary one.
        return self._serialize_block(intercept) + content

    def _extract_intercept_keys(
        self, content: bytes, has_metadata: bool
    ) -> tuple[dict[str, bool], bytes]:
        opts = dict(self._INTERCEPT_KEYS)
        if not content.startswith(b"---\n"):
            return opts, content
        meta, rest = self._parse_block(content)
        kept: dict[str, str] = {}
        for name, value in meta.items():
            if name in self._INTERCEPT_KEYS:
                opts[name] = value.lower() == "true"
            else:
                kept[name] = value
        # Requests keep their (keys-stripped) metadata block; responses drop it.
        cleaned = self._serialize_block(kept) + rest if has_metadata else rest
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
        Open ``path`` in an external editor with the special intercept keys injected.

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

    def _intercept_request(self, f: http.HTTPFlow) -> None:
        path = self.req_path(f)
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
        f.request = request

    def _intercept_response(self, f: http.HTTPFlow) -> None:
        path = self.resp_path(f)
        if path is None:
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
            f.response = self._parse_response_file(cleaned)
        except (ValueError, IndexError) as e:
            logger.error(f"Could not parse edited response: {e}")
            return

    # mitmproxy hooks

    def request(self, f: http.HTTPFlow) -> None:
        self.save_request(f)
        if self.intercept_request:
            self._intercept_request(f)

    def response(self, f: http.HTTPFlow) -> None:
        self.save_response(f)
        if self.intercept_response:
            self._intercept_response(f)
