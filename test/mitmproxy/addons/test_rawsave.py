from mitmproxy.addons import rawsave
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def test_request_and_response(tmp_path):
    ra = rawsave.RawSave(directory=str(tmp_path))
    with taddons.context(ra):
        f = tflow.tflow(resp=True)
        f.request.host = "example.com"
        f.request.port = 443
        f.request.scheme = b"https"
        f.server_conn.sni = "example.com"

        ra.request(f)
        ra.response(f)

    req = (tmp_path / "1.req").read_bytes()
    resp = (tmp_path / "1.resp").read_bytes()

    assert req.startswith(b"---\n")
    assert b"host: example.com\n" in req
    assert b"port: 443\n" in req
    assert b"protocol: https\n" in req
    assert b"sni: example.com\n" in req
    # metadata block is terminated and followed by the raw request
    assert b"\n---\n" in req
    assert req.split(b"---\n", 2)[2].startswith(f.request.method.encode())

    assert resp.startswith(b"HTTP/")
    assert f.response.content in resp


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
