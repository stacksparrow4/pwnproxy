- This project uses uv. Always use `uv run pytest` and don't run pytest directly.
- To run all tests: `uv run tox`.
- When adding new source files, additionally run: `uv run tox -e individual_coverage -- FILENAME`.
- If the environment seems broken (e.g. import errors, missing/corrupted packages like `pytest` or `pygments`), run `uv sync --reinstall` to rebuild it.

## External editor

- The TUI and the proxy share one asyncio loop: never run editors with a blocking
  `subprocess.call`. `spawn_editor_file()` runs the editor embedded in the TUI
  (`mitmproxy/tools/console/editor.py`) and returns a future; rawsave's intercept
  hooks return that awaitable so only the intercepted flow waits.
- `ctrl ]` hides/shows the embedded editor; all other keys go to the editor.
- `"embedded_editor": false` in `~/.pwnproxy/config.json` restores the old blocking behaviour.

## Alpine/nix sandbox quirks

- If `uv sync` tries to build `mitmproxy-rs`/`aioquic` from source (missing
  `bpf-linker` or `openssl/err.h`), the Python from `.python-version` has no musl
  wheels. Use the nix glibc Python in every shell (and tmux session) that runs `uv`:
  `export UV_PYTHON=$(ls /nix/store/*-python3-3.13*-env/bin/python3.13 | head -1)`.
- If `uv run tox` can't find an interpreter, run its commands directly:
  `uv run pytest --timeout 60 -n auto`, `uv run python ./test/individual_coverage.py FILENAME`,
  `uv run mypy`, and `apk add ruff && ruff check .` (the ruff wheel doesn't run on musl).
- `.git` is read-only (no `stash`/`checkout`/`worktree`). To compare against baseline:
  `git archive HEAD | tar -x -C /tmp/base`, then run
  `PYTHONPATH=/tmp/base /root/box/.venv/bin/python -m pytest ...` from `/tmp/base`.
- Pre-existing failures: `test_anticache::test_simple`, `test_mode_servers::test_tun_mode`/`test_wireguard`,
  and `test_termlog::test_cannot_print` (fails whenever a console test module is collected first).

## Manually testing the console TUI in tmux

The interactive `mitmproxy` TUI can be driven headlessly with tmux, which is
useful for reproducing input/rendering bugs (keyboard, mouse, scrolling).

- Start a detached session on an explicit socket (the default socket dir may be
  missing), passing `PATH` so `uv` is found:
  `tmux -S /tmp/mp.sock new-session -d -s mp -x 120 -y 40 -e "PATH=$PATH" -e LANG=C.UTF-8`.
- Generate a flow file to load, e.g. with `mitmproxy.test.tflow` + `mitmproxy.io.FlowWriter`, then launch inside the session:
  `tmux -S /tmp/mp.sock send-keys -t mp "uv run mitmproxy -r /tmp/flows.mitm -p 0" Enter` (give it ~10-15s to boot).
- Flows loaded with `-r` have no saved `.req` files, so `e`/click-to-edit does nothing. To test
  editing, use live traffic: `python3 -m http.server 8999 &`, run mitmproxy with `-p 8123`, then
  `curl -x http://127.0.0.1:8123 http://127.0.0.1:8999/x`. The editor comes from `request_edit_command`
  in `~/.pwnproxy/config.json` (e.g. `"nvim -u NONE {file}"`); back up and restore any existing file.
- Inspect the screen: `tmux -S /tmp/mp.sock capture-pane -t mp -p` (add `-e` to see escape sequences).
  To record the raw bytes mitmproxy writes: `tmux -S /tmp/mp.sock pipe-pane -t mp -O 'cat > /tmp/pane.raw'`.
- Send keystrokes: `tmux -S /tmp/mp.sock send-keys -t mp Down` (or `Up`, `Enter`, a literal key like `"q"`, etc.).
- Send mouse events as raw SGR sequences with `send-keys -l`, where `ESC=$(printf '\033')`:
  - wheel up/down: `"${ESC}[<64;COL;ROWM"` / `"${ESC}[<65;COL;ROWM"`
  - left click press/release: `"${ESC}[<0;COL;ROWM"` then `"${ESC}[<0;COL;ROWm"`
- `ps` can't see processes inside the tmux session; use `/proc/*/stat`. PID 1 doesn't reap
  orphans, so `<defunct>` processes with PPID 1 are expected.
- Clean up when done: `tmux -S /tmp/mp.sock kill-server`.
