import asyncio

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

    req = (tmp_path / "1.req").read_bytes()
    resp = (tmp_path / "1.resp").read_bytes()

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

    req = (tmp_path / "1.req").read_bytes()
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

    header = (tmp_path / "1.req").read_bytes().split(b"---\n", 2)[1]
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

    req = (tmp_path / "1.req").read_bytes()
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

    body = (tmp_path / "1.req").read_bytes().split(b"---\n", 2)[2]
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

    assert (tmp_path / "1.req").exists()
    assert (tmp_path / "1.resp").exists()
    assert (tmp_path / "2.req").exists()
    assert (tmp_path / "2.resp").exists()


def test_resumes_after_existing_files(tmp_path):
    (tmp_path / "3.req").write_bytes(b"old")
    (tmp_path / "1.resp").write_bytes(b"old")
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)
    assert (tmp_path / "4.req").exists()
    assert (tmp_path / "4.resp").exists()


def test_response_without_request(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        ra.response(f)
    # response that arrives without a prior request hook still gets numbered
    assert (tmp_path / "1.resp").exists()


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

    resp = (tmp_path / "1.resp").read_bytes()
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

    head = (tmp_path / "1.resp").read_bytes().partition(b"\n\n")[0]
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

    body = (tmp_path / "1.resp").read_bytes().partition(b"\n\n")[2]
    assert body == b"not-gzip"


def test_missing_content_falls_back_to_head(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.content = None
        f.response.content = None
        ra.request(f)
        ra.response(f)
    assert b"host:" in (tmp_path / "1.req").read_bytes()
    assert (tmp_path / "1.resp").read_bytes().startswith(b"HTTP/")


def test_nonexistent_directory_logs_error(tmp_path, caplog):
    missing = tmp_path / "does" / "not" / "exist"
    # _highest_existing_number handles the missing dir gracefully (returns 0).
    ra = rawsave.RawSave(directory=str(missing))
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
    (tmp_path / "1.req").write_bytes(b"not a valid req file")
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
