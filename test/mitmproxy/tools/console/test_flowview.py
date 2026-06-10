import sys
from unittest import mock

from mitmproxy import http
from mitmproxy.test import tflow
from mitmproxy.tools.console.flowview import FlowDetails


async def test_flowview(console):
    for f in tflow.tflows():
        console.commands.call("view.clear")
        await console.load_flow(f)
        console.type("<enter><tab><tab>")


async def test_flowview_tab_cycle(console):
    f = tflow.tflow()
    await console.load_flow(f)
    console.type("<enter>")
    fv = console.window.current("flowview")
    fd = fv.body
    assert isinstance(fd, FlowDetails)
    n = len(fd.tabs)
    assert fd.tab_offset == 0
    # Tab cycles forward.
    console.type("<tab>")
    assert fd.tab_offset == 1
    # Shift+Tab cycles backward, wrapping around.
    console.type("<shift tab>")
    assert fd.tab_offset == 0
    console.type("<shift tab>")
    assert fd.tab_offset == n - 1


async def test_edit(console, monkeypatch, caplog):
    f = tflow.tflow(
        req=http.Request.make("POST", "http://example.com", b"data"),
    )
    await console.load_flow(f)

    opened = []
    monkeypatch.setattr(console, "spawn_editor_file", lambda path: opened.append(path))

    # console.edit.focus now opens the flow's saved .req file in Neovim.
    rawsave = console.addons.get("rawsave")
    monkeypatch.setattr(rawsave, "req_path", lambda flow: "/tmp/1.req")

    console.type(":console.edit.focus<enter>")
    assert opened == ["/tmp/1.req"]


async def test_content_missing_returns_error(console):
    # message.raw_content is None -> expect "[content missing]" error text
    f_missing = tflow.tflow(
        req=http.Request.make("GET", "http://example.com", b"initial"),
    )
    f_missing.request.raw_content = None

    await console.load_flow(f_missing)

    fd = FlowDetails(console)

    title, txt_objs = fd.content_view("default", f_missing.request)
    assert title == ""

    first_text = txt_objs[0].get_text()[0]
    assert "[content missing]" == first_text


async def test_empty_content_request_and_response(console):
    fd = FlowDetails(console)

    # 1) Request with empty body and no query -> "No request content"
    f_req_empty = tflow.tflow(
        req=http.Request.make("GET", "http://example.com", b""),
    )
    f_req_empty.request.raw_content = b""
    await console.load_flow(f_req_empty)
    title_req, txt_objs_req = fd.content_view("default", f_req_empty.request)
    assert title_req == ""
    req_text = txt_objs_req[0].get_text()[0]
    assert "No request content" == req_text

    # 2) Response with empty body -> "No content"
    f_resp_empty = tflow.tflow(
        req=http.Request.make("GET", "http://example.com", b""),
        resp=http.Response.make(200, b"", {}),
    )
    f_resp_empty.response.raw_content = b""
    await console.load_flow(f_resp_empty)
    title_resp, txt_objs_resp = fd.content_view("default", f_resp_empty.response)
    assert title_resp == ""
    resp_text = txt_objs_resp[0].get_text()[0]
    assert "No content" == resp_text


async def test_content_view_fullcontents_true_uses_unlimited_limit(console):
    f = tflow.tflow(req=http.Request.make("POST", "http://example.com", b"non-empty"))
    await console.load_flow(f)

    fd = FlowDetails(console)

    console.commands.execute("view.settings.setval @focus fullcontents true")
    fd._get_content_view = mock.MagicMock()
    fd.content_view("default", f.request)
    fd._get_content_view.assert_called_with("default", sys.maxsize, mock.ANY)
