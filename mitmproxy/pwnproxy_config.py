"""Loading of the optional pwnproxy ``config.json`` files.

Two locations are read on startup, in order of decreasing priority:

  * ``~/.pwnproxy/config.json`` (local)
  * ``~/.config/pwnproxy/config.json`` (global)

The local file takes precedence over the global one on a per-key basis.
Missing files are silently ignored; malformed files log a warning and are
skipped (the defaults are used instead).

Currently supported keys:

  * ``request_edit_command`` - the command used to open requests/responses in
    an external editor (the intercept editor and the ``e`` hotkey). It may
    contain a ``{file}`` placeholder that is replaced with the path to edit;
    if the placeholder is absent, the path is appended as the final argument.
"""

from __future__ import annotations

import logging
import shlex
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Highest priority first.
CONFIG_PATHS: list[Path] = [
    Path.home() / ".pwnproxy" / "config.json",
    Path.home() / ".config" / "pwnproxy" / "config.json",
]


def _load_file(path: Path) -> dict[str, Any]:
    import json

    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as e:
        logger.warning(f"Could not read pwnproxy config {path}: {e}")
        return {}
    try:
        data = json.loads(raw)
    except ValueError as e:
        logger.warning(f"Ignoring invalid pwnproxy config {path}: {e}")
        return {}
    if not isinstance(data, dict):
        logger.warning(
            f"Ignoring pwnproxy config {path}: expected a JSON object, "
            f"got {type(data).__name__}."
        )
        return {}
    return data


def load_config(paths: list[Path] | None = None) -> dict[str, Any]:
    """Merge the pwnproxy config files into a single dict.

    Keys from higher-priority (earlier) paths win over later ones.
    """
    if paths is None:
        paths = CONFIG_PATHS
    merged: dict[str, Any] = {}
    # Apply lowest priority first so higher-priority files override.
    for path in reversed(paths):
        merged.update(_load_file(path))
    return merged


_config: dict[str, Any] | None = None


def config() -> dict[str, Any]:
    """Return the cached merged config, loading it on first use."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload() -> dict[str, Any]:
    """Force a reload of the config files and return it."""
    global _config
    _config = load_config()
    return _config


def request_edit_command() -> str | None:
    """The configured editor command, or ``None`` if unset/invalid."""
    cmd = config().get("request_edit_command")
    if cmd is None:
        return None
    if not isinstance(cmd, str) or not cmd.strip():
        logger.warning(
            "Ignoring pwnproxy 'request_edit_command': "
            "expected a non-empty string."
        )
        return None
    return cmd


def default_mode() -> list[str]:
    """The default proxy mode(s), from the ``default_mode`` config key.

    Accepts either a single mode string or a list of mode strings (the same
    syntax accepted by ``--mode``). Falls back to ``["regular"]`` when unset or
    invalid. An explicit ``--mode`` on the command line still overrides this.
    """
    value = config().get("default_mode")
    if value is None:
        return ["regular"]
    if isinstance(value, str):
        if value.strip():
            return [value]
    elif (
        isinstance(value, list)
        and value
        and all(isinstance(v, str) and v.strip() for v in value)
    ):
        return list(value)
    logger.warning(
        "Ignoring pwnproxy 'default_mode': expected a non-empty string or "
        "list of non-empty strings."
    )
    return ["regular"]


def always_load() -> bool:
    """Whether saved flows should be restored from disk on startup.

    Controlled by the ``always_load`` config key (default ``False``). Only an
    explicit JSON ``true`` enables it; any other value is treated as disabled
    (a warning is logged for non-boolean values).
    """
    value = config().get("always_load", False)
    if isinstance(value, bool):
        return value
    logger.warning(
        "Ignoring pwnproxy 'always_load': expected a boolean, "
        f"got {type(value).__name__}."
    )
    return False


def build_editor_command(command: str, path: str) -> list[str]:
    """Build the argv list for ``command`` editing ``path``.

    If ``command`` contains a ``{file}`` placeholder it is substituted with
    ``path``; otherwise ``path`` is appended as the final argument.
    """
    parts = shlex.split(command)
    if any("{file}" in part for part in parts):
        return [part.replace("{file}", path) for part in parts]
    parts.append(path)
    return parts
