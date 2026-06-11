import json
import os
import stat
from pathlib import Path

import pytest

from mitmproxy import exceptions
from mitmproxy.addons import rawsave
from mitmproxy.addons import tools
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def _make_tool(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / name
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def in_tmp_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Point HOME at a temporary location so the global tool dir is isolated.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return tmp_path


def test_options_combines_dirs_local_wins(in_tmp_cwd):
    home = Path.home()
    _make_tool(home / ".config" / "pwnproxy" / "tools", "global_tool", "#!/bin/sh\n")
    _make_tool(home / ".config" / "pwnproxy" / "tools", "shared", "#!/bin/sh\necho g")
    _make_tool(in_tmp_cwd / ".pwnproxy" / "tools", "local_tool", "#!/bin/sh\n")
    local_shared = _make_tool(
        in_tmp_cwd / ".pwnproxy" / "tools", "shared", "#!/bin/sh\necho l"
    )

    t = tools.Tools()
    with taddons.context(t):
        assert t.options() == ["global_tool", "local_tool", "shared"]
        # local "shared" wins on collision
        assert t._tools()["shared"].resolve() == local_shared.resolve()


def test_options_empty_when_no_dirs(in_tmp_cwd):
    t = tools.Tools()
    with taddons.context(t):
        assert t.options() == []


def test_run_unknown_tool(in_tmp_cwd):
    t = tools.Tools()
    with taddons.context(t):
        f = tflow.tflow()
        with pytest.raises(exceptions.CommandError, match="No such tool"):
            t.run("nope", [f])


def test_run_feeds_json_and_runs_in_cwd(in_tmp_cwd):
    out = in_tmp_cwd / "out.json"
    _make_tool(
        in_tmp_cwd / ".pwnproxy" / "tools",
        "dump",
        f"#!/bin/sh\ncat > {out}\n",
    )

    ra = rawsave.RawSave(directory=str(in_tmp_cwd / "history"))
    t = tools.Tools()
    with taddons.context(ra, t):
        f = tflow.tflow(resp=True)
        ra.request(f)
        ra.response(f)
        t.run("dump", [f])

    data = json.loads(out.read_text())
    assert data["name"] == ""
    assert data["method"] == f.request.method
    assert data["url"] == f.request.url
    assert data["req"].endswith(".req")
    assert data["resp"].endswith(".resp")
    assert os.path.isabs(data["req"])


def test_run_passes_label_as_name(in_tmp_cwd):
    out = in_tmp_cwd / "out.json"
    _make_tool(
        in_tmp_cwd / ".pwnproxy" / "tools",
        "dump",
        f"#!/bin/sh\ncat > {out}\n",
    )

    t = tools.Tools()
    with taddons.context(t):
        f = tflow.tflow(resp=True)
        t.run("dump", [f], "login-fuzz")

    data = json.loads(out.read_text())
    assert data["name"] == "login-fuzz"


def test_run_ignores_non_http_flows(in_tmp_cwd, caplog):
    _make_tool(in_tmp_cwd / ".pwnproxy" / "tools", "noop", "#!/bin/sh\n")
    t = tools.Tools()
    with taddons.context(t):
        f = tflow.ttcpflow()
        t.run("noop", [f])
    assert "only support HTTP flows" in caplog.text


def test_run_logs_output_and_failure(in_tmp_cwd, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    _make_tool(
        in_tmp_cwd / ".pwnproxy" / "tools",
        "noisy",
        "#!/bin/sh\necho hello\necho oops >&2\nexit 3\n",
    )
    t = tools.Tools()
    with taddons.context(t):
        f = tflow.tflow()
        t.run("noisy", [f])
    assert "noisy: hello" in caplog.text
    assert "noisy: oops" in caplog.text
    assert "exited with status 3" in caplog.text


def test_run_success_logs_finished(in_tmp_cwd, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    _make_tool(in_tmp_cwd / ".pwnproxy" / "tools", "ok", "#!/bin/sh\nexit 0\n")
    t = tools.Tools()
    with taddons.context(t):
        f = tflow.tflow()
        t.run("ok", [f])
    assert "Tool ok finished." in caplog.text


def test_run_handles_oserror(in_tmp_cwd, caplog):
    # A non-executable file cannot be spawned and raises OSError.
    script = in_tmp_cwd / ".pwnproxy" / "tools" / "broken"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("not executable")
    t = tools.Tools()
    with taddons.context(t):
        f = tflow.tflow()
        t.run("broken", [f])
    assert "Error while running tool broken" in caplog.text


def test_run_handles_missing_files(in_tmp_cwd):
    out = in_tmp_cwd / "out.json"
    _make_tool(
        in_tmp_cwd / ".pwnproxy" / "tools",
        "dump",
        f"#!/bin/sh\ncat > {out}\n",
    )
    t = tools.Tools()
    with taddons.context(t):
        # No rawsave addon -> req/resp are null
        f = tflow.tflow(resp=True)
        t.run("dump", [f])

    data = json.loads(out.read_text())
    assert data["req"] is None
    assert data["resp"] is None
