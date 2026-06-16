- This project uses uv. Always use `uv run pytest` and don't run pytest directly.
- To run all tests: `uv run tox`.
- When adding new source files, additionally run: `uv run tox -e individual_coverage -- FILENAME`.
- If the environment seems broken (e.g. import errors, missing/corrupted packages like `pytest` or `pygments`), run `uv sync --reinstall` to rebuild it.

## Manually testing the console TUI in tmux

The interactive `mitmproxy` TUI can be driven headlessly with tmux, which is
useful for reproducing input/rendering bugs (keyboard, mouse, scrolling).

- Start a detached session on an explicit socket (the default socket dir may be
  missing): `tmux -S /tmp/mp.sock new-session -d -s mp -x 120 -y 40`.
- Generate a flow file to load, e.g. with `mitmproxy.test.tflow` + `mitmproxy.io.FlowWriter`, then launch inside the session:
  `tmux -S /tmp/mp.sock send-keys -t mp "uv run mitmproxy -r /tmp/flows.mitm -p 0" Enter` (give it ~10-15s to boot).
- Inspect the screen: `tmux -S /tmp/mp.sock capture-pane -t mp -p`.
- Send keystrokes: `tmux -S /tmp/mp.sock send-keys -t mp Down` (or `Up`, `Enter`, a literal key like `"q"`, etc.).
- Send mouse events as raw SGR sequences with `send-keys -l`, where `ESC=$(printf '\033')`:
  - wheel up/down: `"${ESC}[<64;COL;ROWM"` / `"${ESC}[<65;COL;ROWM"`
  - left click press/release: `"${ESC}[<0;COL;ROWM"` then `"${ESC}[<0;COL;ROWm"`
- Clean up when done: `tmux -S /tmp/mp.sock kill-server`.