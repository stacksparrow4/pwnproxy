import asyncio
from pathlib import Path

from mitmproxy.addons import rawsave
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def test_request_and_response(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.host = "other.example"
        f.request.port = 8443
        f.request.scheme = b"https"
        f.request.headers["Host"] = "example.com"
        f.server_conn.sni = "example.com"

        ra.request(f)
        ra.response(f)

    req = (tmp_path / "000001.req").read_bytes()
    resp = (tmp_path / ".000001.resp").read_bytes()

    assert req.startswith(b"---\n")
    # host differs from Host header, port is non-default => both present
    assert b"host: other.example\n" in req
    assert b"port: 8443\n" in req
    assert b"protocol: https\n" in req
    # sni matches the Host header => omitted
    assert b"sni:" not in req
    # metadata block is terminated and followed by the raw request
    assert b"\n---\n" in req
    assert req.split(b"---\n", 2)[2].startswith(f.request.method.encode())

    assert resp.startswith(b"HTTP/")
    assert f.response.content in resp

    # requests use bare \n line endings, never \r\n
    assert b"\r\n" not in req
    assert b"\r" not in req


def test_defaults_are_omitted(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.host = "example.com"
        f.request.port = 443
        f.request.scheme = b"https"
        f.request.headers["Host"] = "example.com"
        f.server_conn.sni = "example.com"
        ra.request(f)

    req = (tmp_path / "000001.req").read_bytes()
    header = req.split(b"---\n", 2)[1]
    # host matches Host header, port is the https default, sni matches Host header
    assert header == b"protocol: https\n"


def test_http_default_port_omitted(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.host = "example.com"
        f.request.port = 80
        f.request.scheme = b"http"
        f.request.headers["Host"] = "example.com"
        f.server_conn.sni = None
        f.client_conn.sni = None
        ra.request(f)

    header = (tmp_path / "000001.req").read_bytes().split(b"---\n", 2)[1]
    # http default port (80) omitted; empty sni omitted for all HTTP requests
    assert b"port:" not in header
    assert b"sni:" not in header
    assert header == b"protocol: http\n"


def test_http2_uses_origin_form_with_host_header(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.http_version = "HTTP/2.0"
        f.request.scheme = b"https"
        f.request.authority = "example.com"
        f.request.path = "/"
        assert "Host" not in f.request.headers
        ra.request(f)

    req = (tmp_path / "000001.req").read_bytes()
    body = req.split(b"---\n", 2)[2]
    # origin-form request line, not the absolute/proxy form
    assert body.startswith(b"GET / HTTP/2.0\n")
    assert b"https://example.com/" not in body
    # authority restored as a Host header at the top
    assert b"\nHost: example.com\n" in body


def test_connect_keeps_authority_form(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow()
        f.request.method = "CONNECT"
        f.request.authority = "example.com:443"
        ra.request(f)

    body = (tmp_path / "000001.req").read_bytes().split(b"---\n", 2)[2]
    assert body.startswith(b"CONNECT example.com:443 ")


def test_counter_increments_per_flow(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f1 = tflow.tflow(resp=True)
        f2 = tflow.tflow(resp=True)
        ra.request(f1)
        ra.response(f1)
        ra.request(f2)
        ra.response(f2)

    assert (tmp_path / "000001.req").exists()
    assert (tmp_path / ".000001.resp").exists()
    assert (tmp_path / "000002.req").exists()
    assert (tmp_path / ".000002.resp").exists()


def test_resumes_after_existing_files(tmp_path):
    (tmp_path / "000003.req").write_bytes(b"old")
    (tmp_path / ".000001.resp").write_bytes(b"old")
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)
    assert (tmp_path / "000004.req").exists()
    assert (tmp_path / ".000004.resp").exists()


def test_response_without_request(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.response(f)
    # response that arrives without a prior request hook still gets numbered
    assert (tmp_path / ".000001.resp").exists()


def test_no_response(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow()
        assert f.response is None
        ra.response(f)
    assert not list(tmp_path.iterdir())


def test_response_body_is_decoded(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.response.headers["content-encoding"] = "gzip"
        # Assigning .content re-encodes using the content-encoding header,
        # so raw_content ends up gzip-compressed on the wire.
        f.response.content = b"hello decoded world"
        assert f.response.raw_content != b"hello decoded world"
        ra.response(f)

    resp = (tmp_path / ".000001.resp").read_bytes()
    head, _, body = resp.partition(b"\n\n")
    assert body == b"hello decoded world"
    # encoding header stripped, content-length matches the decoded body
    assert b"content-encoding" not in head.lower()
    assert b"content-length: 19" in head.lower()
    # the head uses bare \n line endings, no \r
    assert b"\r" not in head


def test_chunked_transfer_encoding_is_removed(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.response.headers["transfer-encoding"] = "chunked"
        ra.response(f)

    head = (tmp_path / ".000001.resp").read_bytes().partition(b"\n\n")[0]
    assert b"transfer-encoding" not in head.lower()
    assert b"content-length:" in head.lower()


def test_undecodable_response_kept_as_is(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.response.headers["content-encoding"] = "gzip"
        # Not actually valid gzip data => cannot be decoded.
        f.response.raw_content = b"not-gzip"
        ra.response(f)

    body = (tmp_path / ".000001.resp").read_bytes().partition(b"\n\n")[2]
    assert body == b"not-gzip"


def test_missing_content_falls_back_to_head(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.content = None
        f.response.content = None
        ra.request(f)
        ra.response(f)
    assert b"host:" in (tmp_path / "000001.req").read_bytes()
    assert (tmp_path / ".000001.resp").read_bytes().startswith(b"HTTP/")


def test_default_directory_is_history():
    assert rawsave.RawSave().directory == Path("history")


def test_creates_history_directory_on_write(tmp_path):
    history = tmp_path / "history"
    assert not history.exists()
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)
    assert history.is_dir()
    assert (history / "000001.req").exists()
    assert (history / ".000001.resp").exists()


def test_uncreatable_directory_logs_error(tmp_path, caplog):
    # A regular file blocks creation of the directory below it, so mkdir fails.
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"")
    ra = rawsave.RawSave(directory=str(blocker / "sub"))
    assert ra.counter == 0
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)
    assert "Error while writing" in caplog.text


async def test_restore_roundtrip(tmp_path):
    # First, save a flow.
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.host = "example.com"
        f.request.port = 443
        f.request.scheme = b"https"
        f.request.method = "GET"
        f.request.path = "/"
        f.request.http_version = "HTTP/1.1"
        f.request.headers["Host"] = "example.com"
        f.request.content = b"hello"
        f.server_conn.sni = "example.com"
        f.response.status_code = 200
        f.response.headers["content-type"] = "text/html"
        f.response.content = b"<html></html>"
        ra.request(f)
        ra.response(f)

    # Now restore in a fresh addon instance.
    ra2 = rawsave.RawSave(directory=str(tmp_path))
    flows = ra2._restored_flows()
    assert len(flows) == 1
    rf = flows[0]
    assert rf.request.method == "GET"
    assert rf.request.path == "/"
    assert rf.request.http_version == "HTTP/1.1"
    assert rf.request.host == "example.com"
    assert rf.request.port == 443
    assert rf.request.scheme == "https"
    assert rf.request.headers["Host"] == "example.com"
    assert rf.request.content == b"hello"
    assert rf.server_conn.sni == "example.com"
    assert rf.response is not None
    assert rf.response.status_code == 200
    assert rf.response.reason == "OK"
    assert rf.response.headers["content-type"] == "text/html"
    assert rf.response.content == b"<html></html>"


async def test_restore_loads_flows(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)

    ra2 = rawsave.RawSave(directory=str(tmp_path))
    loaded = []
    with taddons.context(ra2) as tctx:

        async def fake_load_flow(flow):
            loaded.append(flow)

        tctx.master.load_flow = fake_load_flow
        await ra2.restore()
    assert len(loaded) == 1
    # restored flows are tracked so they are not re-saved
    assert loaded[0].id in ra2.restored_ids


def test_restored_flows_are_not_resaved(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)

    ra2 = rawsave.RawSave(directory=str(tmp_path))
    restored = ra2._restored_flows()[0]
    before = sorted(p.name for p in tmp_path.iterdir())
    # Replaying lifecycle events for a restored flow must not write new files.
    ra2.request(restored)
    ra2.response(restored)
    after = sorted(p.name for p in tmp_path.iterdir())
    assert before == after


def test_connect_request_restores_authority_form(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow()
        f.request.method = "CONNECT"
        f.request.authority = "example.com:443"
        ra.request(f)

    ra2 = rawsave.RawSave(directory=str(tmp_path))
    rf = ra2._restored_flows()[0]
    assert rf.request.method == "CONNECT"
    assert rf.request.authority == "example.com:443"


def test_restore_skips_corrupt_files(tmp_path, caplog):
    (tmp_path / "000001.req").write_bytes(b"not a valid req file")
    ra = rawsave.RawSave(directory=str(tmp_path))
    assert ra._restored_flows() == []
    assert "Could not restore" in caplog.text


def test_restore_missing_directory(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path / "missing"))
    assert ra._restored_flows() == []


def test_parse_headers_skips_empty_lines():
    headers = rawsave.RawSave._parse_headers([b"Host: example.com", b"", b"X-Test: y"])
    assert headers["Host"] == "example.com"
    assert headers["X-Test"] == "y"
    assert len(headers.fields) == 2


async def test_running_schedules_restore(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)

    ra2 = rawsave.RawSave(directory=str(tmp_path))
    loaded = []
    with taddons.context(ra2) as tctx:

        async def fake_load_flow(flow):
            loaded.append(flow)

        tctx.master.load_flow = fake_load_flow
        ra2.running()
        await asyncio.sleep(0.01)
    assert len(loaded) == 1


def test_req_path(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        # unknown flow -> no path
        assert ra.req_path(f) is None
        ra.request(f)
        assert ra.req_path(f) == tmp_path / "000001.req"

    # number known but file removed -> None
    (tmp_path / "000001.req").unlink()
    assert ra.req_path(f) is None


def test_req_path_for_restored_flow(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)

    ra2 = rawsave.RawSave(directory=str(tmp_path))
    restored = ra2._restored_flows()[0]
    assert ra2.req_path(restored) == tmp_path / "000001.req"


def test_filename_zero_padding():
    assert rawsave.RawSave._name(1, "req") == "000001.req"
    assert rawsave.RawSave._name(42, "resp") == ".000042.resp"
    assert rawsave.RawSave._name(1234567, "req") == "1234567.req"


def test_replay_copies_files(tmp_path, monkeypatch, caplog):
    import logging as _logging
    monkeypatch.chdir(tmp_path)
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)

        replay = tmp_path / "replay"
        assert not replay.exists()
        with caplog.at_level(_logging.INFO):
            ra.replay([f])

    assert (replay / "000001.req").read_bytes() == (history / "000001.req").read_bytes()
    assert (replay / ".000001.resp").read_bytes() == (
        history / ".000001.resp"
    ).read_bytes()
    assert "replay/000001.req" in caplog.text


def test_replay_named(tmp_path, monkeypatch, caplog):
    import logging as _logging
    monkeypatch.chdir(tmp_path)
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)

        replay = tmp_path / "replay"
        with caplog.at_level(_logging.INFO):
            ra.replay([f], "myname")

    assert (replay / "myname.req").read_bytes() == (history / "000001.req").read_bytes()
    assert (replay / ".myname.resp").read_bytes() == (
        history / ".000001.resp"
    ).read_bytes()
    assert not (replay / "000001.req").exists()
    assert "replay/myname.req" in caplog.text


def test_replay_request_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra):
        f = tflow.tflow()  # no response
        ra.request(f)
        ra.replay([f])

    replay = tmp_path / "replay"
    assert (replay / "000001.req").exists()
    assert not (replay / ".000001.resp").exists()


def test_replay_unknown_flow_warns(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    ra = rawsave.RawSave(directory=str(tmp_path / "history"))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)  # never saved -> no number
        ra.replay([f])
    assert "No saved request file" in caplog.text
    assert not (tmp_path / "replay").exists()


def test_replay_copy_error_logged(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        # Block creation of the replay directory by putting a file in its place.
        (tmp_path / "replay").write_bytes(b"")
        ra.replay([f])
    assert "Error while copying" in caplog.text


def test_intercept_toggle(caplog):
    import logging as _logging
    ra = rawsave.RawSave()
    with taddons.context(ra), caplog.at_level(_logging.INFO):
        assert ra.intercept_request is False
        ra.intercept_toggle()
        assert ra.intercept_request is True
        assert "Request intercept: on" in caplog.text
        ra.intercept_toggle()
        assert ra.intercept_request is False

        ra.intercept_response_toggle()
        assert ra.intercept_response is True
        assert "Response intercept: on" in caplog.text
        ra.intercept_response_toggle()
        assert ra.intercept_response is False


def _fake_editor(new_content):
    """Return a spawn_editor_file replacement that overwrites the file."""
    def editor(path):
        Path(path).write_bytes(new_content)
    return editor


def test_intercept_request_edits_flow(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow()
        f.request.method = "GET"
        f.request.path = "/"
        f.request.headers["Host"] = "example.com"

        edited = (
            b"---\nprotocol: http\n---\n"
            b"POST /edited HTTP/1.1\nHost: example.com\n\nhello"
        )
        tctx.master.spawn_editor_file = _fake_editor(edited)

        ra.intercept_toggle()
        ra.request(f)

    # original saved alongside the edited version
    assert (history / "000001.req.orig").exists()
    assert (history / "000001.req").read_bytes() == edited
    # the live flow now carries the edited request, which will be sent as normal
    assert f.request.method == "POST"
    assert f.request.path == "/edited"
    assert f.request.content == b"hello"


def test_intercept_response_edits_flow(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow(resp=True)

        edited = b"HTTP/1.1 404 Not Found\ncontent-length: 3\n\nbye"
        tctx.master.spawn_editor_file = _fake_editor(edited)

        ra.request(f)
        ra.intercept_response_toggle()
        ra.response(f)

    assert (history / ".000001.resp.orig").exists()
    assert (history / ".000001.resp").read_bytes() == edited
    assert f.response.status_code == 404
    assert f.response.content == b"bye"


def test_intercept_without_console_warns(tmp_path, caplog):
    ra = rawsave.RawSave(directory=str(tmp_path / "history"))
    with taddons.context(ra) as tctx:
        # RecordingMaster has no spawn_editor_file
        assert not hasattr(tctx.master, "spawn_editor_file")
        f = tflow.tflow()
        ra.request(f)
        ra.intercept_toggle()
        ra.request(f)
    assert "requires the console interface" in caplog.text


def test_intercept_request_no_file_noop(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path / "history"))
    with taddons.context(ra):
        f = tflow.tflow()
        # never saved -> req_path is None -> intercept is a no-op
        ra._intercept_request(f)
    assert not (tmp_path / "history").exists()


def test_intercept_response_no_file_noop(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path / "history"))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra._intercept_response(f)  # unknown number -> no-op


def test_intercept_edit_unparsable_logs_error(tmp_path, caplog):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow()
        tctx.master.spawn_editor_file = _fake_editor(b"garbage without delimiter")
        ra.intercept_toggle()
        before = f.request.method
        ra.request(f)
    assert "Could not parse edited request" in caplog.text
    assert f.request.method == before


def test_intercept_edit_io_error_logged(tmp_path, caplog):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow()
        ra.request(f)
        path = ra.req_path(f)

        def boom(p):
            raise OSError("nope")

        tctx.master.spawn_editor_file = boom
        assert ra._run_intercept(path, has_metadata=True) is None
    assert "Error while editing" in caplog.text


def test_intercept_response_missing_file_noop(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)  # assigns a number and writes .req, but not .resp
        assert not (history / ".000001.resp").exists()
        ra._intercept_response(f)  # number known, .resp missing -> no-op


def test_intercept_response_without_console_warns(tmp_path, caplog):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra):  # RecordingMaster has no spawn_editor_file
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)
        ra._intercept_response(f)
    assert "requires the console interface" in caplog.text


def test_intercept_response_unparsable_logs_error(tmp_path, caplog):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)
        before = f.response.status_code
        tctx.master.spawn_editor_file = _fake_editor(b"garbage")
        ra._intercept_response(f)
    assert "Could not parse edited response" in caplog.text
    assert f.response.status_code == before


def test_intercept_unmodified_no_orig(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow()
        # editor that leaves the file untouched (no modification)
        tctx.master.spawn_editor_file = lambda path: None
        ra.intercept_toggle()
        ra.request(f)
    assert (history / "000001.req").exists()
    assert not (history / "000001.req.orig").exists()


def _capturing_editor(seen, transform=lambda b: b):
    """Editor stub: records the opened content and writes back transform(content)."""
    def editor(path):
        data = Path(path).read_bytes()
        seen.append(data)
        Path(path).write_bytes(transform(data))
    return editor


def test_intercept_injects_keys_not_persisted(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow()
        f.request.headers["Host"] = "example.com"
        seen = []
        tctx.master.spawn_editor_file = _capturing_editor(seen)  # identity edit
        ra.intercept_toggle()
        ra.request(f)

    # the file opened in Neovim contains the special keys inside the --- block
    assert seen[0].startswith(b"---\n")
    assert b"stop_intercepting: false" in seen[0]
    assert b"update_content_length: true" in seen[0]

    # ... but the persisted .req does not, and an unmodified edit leaves no .orig
    saved = (history / "000001.req").read_bytes()
    assert b"stop_intercepting" not in saved
    assert b"update_content_length" not in saved
    assert not (history / "000001.req.orig").exists()


def test_intercept_response_gets_metadata_section(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow(resp=True)
        seen = []
        tctx.master.spawn_editor_file = _capturing_editor(seen)
        ra.request(f)
        ra.intercept_response_toggle()
        ra.response(f)

    # the response file shown in Neovim gets a --- block with the special keys
    assert seen[0].startswith(b"---\n")
    assert b"stop_intercepting: false" in seen[0]
    # the saved .resp keeps neither the --- block nor the keys
    saved = (history / ".000001.resp").read_bytes()
    assert not saved.startswith(b"---")
    assert b"stop_intercepting" not in saved


def test_stop_intercepting_discards_edits_and_disables(tmp_path, caplog):
    import logging as _logging
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx, caplog.at_level(_logging.INFO):
        f = tflow.tflow()
        f.request.method = "GET"
        f.request.headers["Host"] = "example.com"

        def transform(data):
            data = data.replace(b"stop_intercepting: false", b"stop_intercepting: true")
            return data.replace(b"GET ", b"DELETE ")  # edit that must be ignored

        tctx.master.spawn_editor_file = _capturing_editor([], transform)
        ra.intercept_toggle()
        assert ra.intercept_request is True
        ra.request(f)

    # edits ignored: the flow forwards unchanged
    assert f.request.method == "GET"
    # intercept mode turned off
    assert ra.intercept_request is False
    assert "Request intercept: off" in caplog.text
    # the original file is left intact, with no .orig
    assert not (history / "000001.req.orig").exists()
    assert b"DELETE" not in (history / "000001.req").read_bytes()


def test_update_content_length_true_corrects(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow()
        assert "content-length" in f.request.headers  # tflow default has one

        def transform(data):
            head, _, _ = data.partition(b"\n\n")
            return head + b"\n\nlongerbody"

        tctx.master.spawn_editor_file = _capturing_editor([], transform)
        ra.intercept_toggle()
        ra.request(f)

    assert f.request.content == b"longerbody"
    assert f.request.headers["content-length"] == str(len(b"longerbody"))


def test_update_content_length_false_preserves(tmp_path):
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx:
        f = tflow.tflow()
        original_cl = f.request.headers["content-length"]

        def transform(data):
            data = data.replace(
                b"update_content_length: true", b"update_content_length: false"
            )
            head, _, _ = data.partition(b"\n\n")
            return head + b"\n\nlongerbody"

        tctx.master.spawn_editor_file = _capturing_editor([], transform)
        ra.intercept_toggle()
        ra.request(f)

    assert f.request.content == b"longerbody"
    # content-length left as the (now incorrect) edited value
    assert f.request.headers["content-length"] == original_cl


def test_stop_intercepting_response_disables(tmp_path, caplog):
    import logging as _logging
    history = tmp_path / "history"
    ra = rawsave.RawSave(directory=str(history))
    with taddons.context(ra) as tctx, caplog.at_level(_logging.INFO):
        f = tflow.tflow(resp=True)
        original_status = f.response.status_code

        def transform(data):
            data = data.replace(b"stop_intercepting: false", b"stop_intercepting: true")
            return data.replace(b"200", b"500")  # edit that must be ignored

        tctx.master.spawn_editor_file = _capturing_editor([], transform)
        ra.request(f)
        ra.intercept_response_toggle()
        assert ra.intercept_response is True
        ra.response(f)

    assert f.response.status_code == original_status
    assert ra.intercept_response is False
    assert "Response intercept: off" in caplog.text
    assert not (history / ".000001.resp.orig").exists()


import os as _os


def test_map_symlink_created(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ra = rawsave.RawSave()  # history/ in cwd
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.scheme = b"https"
        f.request.host = "example.com"
        f.request.path = "/test"
        ra.request(f)
        ra.response(f)

    link_req = tmp_path / "map" / "example.com" / "test" / "000001.req"
    link_resp = tmp_path / "map" / "example.com" / "test" / ".000001.resp"
    assert link_req.is_symlink()
    assert link_resp.is_symlink()
    # points at the history file via a relative path
    assert _os.readlink(link_req) == _os.path.join(
        "..", "..", "..", "history", "000001.req"
    )
    # symlink resolves to the actual saved request
    assert link_req.resolve() == (tmp_path / "history" / "000001.req").resolve()
    assert link_req.read_bytes() == (tmp_path / "history" / "000001.req").read_bytes()


def test_map_nested_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ra = rawsave.RawSave()
    with taddons.context(ra):
        f = tflow.tflow()
        f.request.scheme = b"https"
        f.request.host = "example.com"
        f.request.path = "/test/test2"
        ra.request(f)

    link = tmp_path / "map" / "example.com" / "test" / "test2" / "000001.req"
    assert link.is_symlink()
    assert _os.readlink(link) == _os.path.join(
        "..", "..", "..", "..", "history", "000001.req"
    )


def test_map_query_string_ignored(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ra = rawsave.RawSave()
    with taddons.context(ra):
        f = tflow.tflow()
        f.request.scheme = b"https"
        f.request.host = "example.com"
        f.request.path = "/test?id=1"
        ra.request(f)

    assert (tmp_path / "map" / "example.com" / "test" / "000001.req").is_symlink()
    assert not (tmp_path / "map" / "example.com" / "test").joinpath("id=1").exists()


def test_map_root_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ra = rawsave.RawSave()
    with taddons.context(ra):
        f = tflow.tflow()
        f.request.scheme = b"https"
        f.request.host = "example.com"
        f.request.path = "/"
        ra.request(f)

    link = tmp_path / "map" / "example.com" / "000001.req"
    assert link.is_symlink()
    assert _os.readlink(link) == _os.path.join("..", "..", "history", "000001.req")


def test_map_traversal_segments_sanitised(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ra = rawsave.RawSave()
    with taddons.context(ra):
        f = tflow.tflow()
        f.request.scheme = b"https"
        f.request.host = "example.com"
        # %2e%2e decodes to ".." which must not escape the map directory
        f.request.path = "/%2e%2e/x"
        ra.request(f)

    # ".." segment dropped; only "x" remains
    assert (tmp_path / "map" / "example.com" / "x" / "000001.req").is_symlink()
    assert not (tmp_path / "map" / "000001.req").exists()


def test_map_symlink_error_logged(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    ra = rawsave.RawSave()
    with taddons.context(ra):
        f = tflow.tflow()
        f.request.host = "example.com"
        f.request.path = "/test"

        def boom(self, *a, **k):
            raise OSError("nope")

        monkeypatch.setattr(rawsave.Path, "mkdir", boom)
        ra.request(f)
    assert "Error while creating map symlink" in caplog.text
