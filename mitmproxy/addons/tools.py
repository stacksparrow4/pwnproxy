import json
import logging
import subprocess
from collections.abc import Sequence
from pathlib import Path

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.log import ALERT

logger = logging.getLogger(__name__)


class Tools:
    """
    Run user-provided "tool" scripts against the currently selected HTTP flow.

    Tools are standalone executable scripts discovered from two directories:

      * ``~/.config/pwnproxy/tools/`` (global)
      * ``./.pwnproxy/tools/`` (project-local, relative to the current working
        directory)

    The combined tool list is keyed by file name; on a name collision the
    project-local script wins.

    When a tool is run, a small JSON document describing the flow is fed to the
    script's STDIN:

        {
            "method": "GET",
            "url": "https://example.com/foo?bar=baz",
            "req": "/abs/path/to/000001.req",
            "resp": "/abs/path/to/.000001.resp"
        }

    ``req``/``resp`` may be ``null`` if the corresponding file is unavailable.
    The script is run with the current working directory of mitmproxy.
    """

    def _tool_dirs(self) -> list[Path]:
        # Ordered from lowest to highest precedence; the project-local
        # directory is listed last so it overrides the global one on a name
        # collision.
        return [
            Path.home() / ".config" / "pwnproxy" / "tools",
            Path(".pwnproxy") / "tools",
        ]

    def _tools(self) -> dict[str, Path]:
        """Map tool name -> script path, project-local taking precedence."""
        tools: dict[str, Path] = {}
        for directory in self._tool_dirs():
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_file():
                    tools[entry.name] = entry
        return tools

    @command.command("tools.options")
    def options(self) -> Sequence[str]:
        """Return the names of all available tools."""
        return sorted(self._tools())

    @command.command("tools.run")
    def run(self, name: str, flows: Sequence[flow.Flow]) -> None:
        """Run the named tool against the given flow(s)."""
        script = self._tools().get(name)
        if script is None:
            raise exceptions.CommandError(f"No such tool: {name}")
        for f in flows:
            if not isinstance(f, http.HTTPFlow):
                logger.warning("Tools only support HTTP flows.")
                continue
            self._run_one(script, f)

    def _run_one(self, script: Path, flow: http.HTTPFlow) -> None:
        rawsave = ctx.master.addons.get("rawsave")
        req_path = rawsave.req_path(flow) if rawsave else None
        resp_path = rawsave.resp_path(flow) if rawsave else None

        payload = {
            "method": flow.request.method,
            "url": flow.request.url,
            "req": str(req_path.resolve()) if req_path else None,
            "resp": str(resp_path.resolve()) if resp_path else None,
        }
        data = json.dumps(payload).encode()

        try:
            proc = subprocess.run(
                [str(script.resolve())],
                input=data,
                capture_output=True,
                check=False,
            )
        except OSError as e:
            logger.error(f"Error while running tool {script.name}: {e}")
            return

        for line in proc.stdout.decode(errors="replace").splitlines():
            logging.log(ALERT, f"{script.name}: {line}")
        for line in proc.stderr.decode(errors="replace").splitlines():
            logger.warning(f"{script.name}: {line}")
        if proc.returncode != 0:
            logger.error(f"Tool {script.name} exited with status {proc.returncode}.")
        else:
            logging.log(ALERT, f"Tool {script.name} finished.")
