import json
import logging

import pytest

from mitmproxy import pwnproxy_config


@pytest.fixture(autouse=True)
def _reset_cache():
    # Ensure each test starts without a cached config.
    pwnproxy_config._config = None
    yield
    pwnproxy_config._config = None


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_text(json.dumps(data), encoding="utf-8")


def test_load_missing(tmp_path):
    local = tmp_path / "local.json"
    glob = tmp_path / "global.json"
    assert pwnproxy_config.load_config([local, glob]) == {}


def test_local_overrides_global(tmp_path):
    local = tmp_path / "local.json"
    glob = tmp_path / "global.json"
    _write(local, {"request_edit_command": "nvim {file}"})
    _write(glob, {"request_edit_command": "vim {file}", "other": 1})

    merged = pwnproxy_config.load_config([local, glob])
    assert merged["request_edit_command"] == "nvim {file}"
    assert merged["other"] == 1


def test_global_used_when_local_absent(tmp_path):
    local = tmp_path / "local.json"
    glob = tmp_path / "global.json"
    _write(glob, {"request_edit_command": "vim {file}"})

    merged = pwnproxy_config.load_config([local, glob])
    assert merged["request_edit_command"] == "vim {file}"


def test_invalid_json_warns_and_skips(tmp_path, caplog):
    local = tmp_path / "local.json"
    glob = tmp_path / "global.json"
    _write(local, "{not valid json")
    _write(glob, {"request_edit_command": "vim {file}"})

    with caplog.at_level(logging.WARNING):
        merged = pwnproxy_config.load_config([local, glob])
    assert merged["request_edit_command"] == "vim {file}"
    assert "invalid pwnproxy config" in caplog.text


def test_non_object_json_warns_and_skips(tmp_path, caplog):
    local = tmp_path / "local.json"
    _write(local, [1, 2, 3])
    with caplog.at_level(logging.WARNING):
        merged = pwnproxy_config.load_config([local])
    assert merged == {}
    assert "expected a JSON object" in caplog.text


def test_oserror_warns_and_skips(tmp_path, caplog):
    # A path that exists but cannot be read as a file (it's a directory)
    # triggers an OSError that is not FileNotFoundError.
    bad = tmp_path / "adir"
    bad.mkdir()
    with caplog.at_level(logging.WARNING):
        assert pwnproxy_config.load_config([bad]) == {}
    assert "Could not read pwnproxy config" in caplog.text


def test_config_loads_on_first_use(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    _write(path, {"request_edit_command": "vim {file}"})
    monkeypatch.setattr(pwnproxy_config, "CONFIG_PATHS", [path])
    pwnproxy_config._config = None
    assert pwnproxy_config.config()["request_edit_command"] == "vim {file}"


def test_request_edit_command(tmp_path, monkeypatch):
    monkeypatch.setattr(
        pwnproxy_config, "_config", {"request_edit_command": "nvim {file}"}
    )
    assert pwnproxy_config.request_edit_command() == "nvim {file}"


def test_request_edit_command_unset(monkeypatch):
    monkeypatch.setattr(pwnproxy_config, "_config", {})
    assert pwnproxy_config.request_edit_command() is None


@pytest.mark.parametrize("value", ["", "   ", 123, None, ["nvim"]])
def test_request_edit_command_invalid(monkeypatch, value):
    cfg = {} if value is None else {"request_edit_command": value}
    monkeypatch.setattr(pwnproxy_config, "_config", cfg)
    assert pwnproxy_config.request_edit_command() is None


def test_default_mode_unset(monkeypatch):
    monkeypatch.setattr(pwnproxy_config, "_config", {})
    assert pwnproxy_config.default_mode() == ["regular"]


def test_default_mode_string(monkeypatch):
    monkeypatch.setattr(pwnproxy_config, "_config", {"default_mode": "transparent"})
    assert pwnproxy_config.default_mode() == ["transparent"]


def test_default_mode_list(monkeypatch):
    monkeypatch.setattr(
        pwnproxy_config,
        "_config",
        {"default_mode": ["regular", "reverse:https://example.com"]},
    )
    assert pwnproxy_config.default_mode() == [
        "regular",
        "reverse:https://example.com",
    ]


@pytest.mark.parametrize("value", ["", "  ", [], ["regular", ""], [1], 5, {}])
def test_default_mode_invalid(monkeypatch, value, caplog):
    monkeypatch.setattr(pwnproxy_config, "_config", {"default_mode": value})
    with caplog.at_level(logging.WARNING):
        assert pwnproxy_config.default_mode() == ["regular"]
    assert "default_mode" in caplog.text


def test_always_load_default(monkeypatch):
    monkeypatch.setattr(pwnproxy_config, "_config", {})
    assert pwnproxy_config.always_load() is False


def test_always_load_true(monkeypatch):
    monkeypatch.setattr(pwnproxy_config, "_config", {"always_load": True})
    assert pwnproxy_config.always_load() is True


@pytest.mark.parametrize("value", ["true", 1, None, []])
def test_always_load_invalid(monkeypatch, value, caplog):
    monkeypatch.setattr(pwnproxy_config, "_config", {"always_load": value})
    with caplog.at_level(logging.WARNING):
        assert pwnproxy_config.always_load() is False
    assert "always_load" in caplog.text


def test_build_editor_command_placeholder():
    assert pwnproxy_config.build_editor_command("nvim {file}", "/tmp/x") == [
        "nvim",
        "/tmp/x",
    ]
    assert pwnproxy_config.build_editor_command(
        "code --wait --file={file}", "/tmp/x"
    ) == ["code", "--wait", "--file=/tmp/x"]


def test_build_editor_command_appends_when_no_placeholder():
    assert pwnproxy_config.build_editor_command("vim -p", "/tmp/x") == [
        "vim",
        "-p",
        "/tmp/x",
    ]


def test_reload(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    _write(path, {"request_edit_command": "vim {file}"})
    monkeypatch.setattr(pwnproxy_config, "CONFIG_PATHS", [path])
    assert pwnproxy_config.reload()["request_edit_command"] == "vim {file}"
    assert pwnproxy_config.config()["request_edit_command"] == "vim {file}"
