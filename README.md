# pwnproxy

`pwnproxy` is a fork of [mitmproxy](https://github.com/mitmproxy/mitmproxy)
geared towards web/security testing workflows. It turns the mitmproxy console
into a Burp-style interception and tinkering tool: every request/response is
saved to disk as editable raw HTTP, flows can be edited and replayed in Neovim,
and custom "tools" can be run against the selected flow.

This document summarizes all changes in this fork relative to upstream
mitmproxy (commit `c4a42d4d5c5de847cb3292fc1a9d9d3bbca54d0e`).

## New features

### Raw request/response saving (`mitmproxy/addons/rawsave.py`)

A new `RawSave` addon (registered by default) persists every HTTP request and
response to disk as numbered, zero-padded files in a `history/` directory in
the current working directory:

- `000001.req` — the raw HTTP request, prefixed with a `---`-delimited
  metadata block describing the connection (`host`, `port`, `protocol`,
  `sni`), with bare `\n` line endings.
- `000001.req.resp` — the raw HTTP response, with the body decoded
  (un-gzipped/un-brotli'd), `Content-Encoding`/`Transfer-Encoding` stripped,
  and `Content-Length` fixed to the decoded body size.

Additional behavior:

- **Map directory**: each saved file is also symlinked under a `map/`
  directory whose structure mirrors the request host and path
  (e.g. `map/example.com/test/000001.req`). Path traversal segments are
  sanitized.
- **Save & restore**: previously saved `history/*.req` (and matching `.resp`)
  files can be parsed back into flows and restored into the view. This is
  **opt-in** and disabled by default: pass `--load` on startup, or set
  `"always_load": true` in `config.json` (see Configuration below). Either way
  the file numbering continues after the highest existing number so nothing is
  clobbered.
- **Replay** (`rawsave.replay`): copies the saved `.req`/`.resp` files for the
  selected flow(s) into a `replay/` directory. An optional name lets you save
  them as `replay/<name>.req` / `replay/<name>.req.resp`.
- **Burp-style interactive intercept**: `rawsave.intercept.toggle` and
  `rawsave.intercept.response.toggle` open each request/response in your
  configured editor (see `request_edit_command` below) for
  editing before it is forwarded. Special intercept-only keys
  (`stop_intercepting`, `update_content_length`) can be set in the `---` block
  while editing; they are never written to disk. `Content-Length` is
  recomputed automatically unless disabled.
- Helper commands `req_path` / `resp_path` expose the on-disk paths for other
  addons (used by `tools` and the editor integration).

### Configuration (`config.json`)

On startup pwnproxy reads an optional `config.json` from two locations, in
decreasing order of priority:

- `~/.pwnproxy/config.json` (local; wins on key collision)
- `~/.config/pwnproxy/config.json` (global)

Missing files are ignored; malformed files log a warning and are skipped.

Supported keys:

- `request_edit_command`: the command used to open requests/responses in an
  external editor (both the interactive intercept and the `e` hotkey). A
  `{file}` placeholder is replaced with the path to edit; if absent, the path
  is appended as the final argument. If unset, `$EDITOR` is used, then a
  sensible fallback (`sensible-editor`/`nano`/`vim`).
- `always_load` (boolean, default `false`): restore previously saved flows from
  the history directory on startup. Equivalent to passing `--load`. The
  `--load` flag takes effect even when this is unset.

```json
{
    "request_edit_command": "nvim {file}",
    "always_load": true
}
```

### Tools (`mitmproxy/addons/tools.py`)

A new `Tools` addon lets you run user-provided executable scripts against the
selected flow. Tools are discovered from:

- `~/.config/pwnproxy/tools/` (global)
- `./.pwnproxy/tools/` (project-local; wins on name collision)

Pressing `t` in the flow list lets you pick a tool and supply an optional
label. The tool is run with a JSON document on STDIN:

```json
{
    "name": "login-fuzz",
    "method": "GET",
    "url": "https://example.com/foo?bar=baz",
    "req":  "/abs/path/to/000001.req",
    "resp": "/abs/path/to/000001.req.resp"
}
```

Tool stdout is shown in the event log (as alerts); stderr as warnings. An
example tool that generates an [ffuf](https://github.com/ffuf/ffuf) wrapper
script is included at `examples/tools/ffuf`.

### Neovim editing

- `e` opens the focused flow's saved `.req` file directly in Neovim
  (`console.edit.focus` / `master.spawn_editor_file`), replacing the old
  per-component editing submenu.

### SOCKS5 upstream proxy support

Upstream mode can now forward to an upstream SOCKS5 proxy:

```shell
mitmdump --mode upstream:socks5://proxy:1080
```

- `mitmproxy/net/server_spec.py`: adds the `socks5` scheme (default port 1080).
- `mitmproxy/proxy/mode_specs.py`: `UpstreamMode` accepts `socks5`;
  `ReverseMode` explicitly rejects it.
- `mitmproxy/proxy/layers/http/_upstream_proxy.py`: implements the SOCKS5
  handshake (and tunneling).
- `mitmproxy/addons/upstream_auth.py`: when the upstream is SOCKS5,
  `--upstream-auth` credentials are sent during the SOCKS5
  username/password handshake instead of as a `Proxy-Authorization` header.

## Console / UI changes

- **Follow mode by default**: `console_focus_follow` now defaults to `True`
  (focus follows new flows).
- **Mouse-wheel scrolling**: scrolling the flow list with the mouse wheel now
  scrolls the viewport like a webpage instead of moving the selection. Follow
  mode keeps working while scrolled to the bottom. (`flowlist.py`)
- **Request ID column**: the flow list shows the zero-padded request number
  (e.g. `000001`) for each flow. (`common.py`, `flowlist.py`)
- **Tab navigation**: `shift+tab` cycles the flow detail tabs in reverse
  (`console.nav.prev` / `m_prev`); opening a flow always starts on the first
  (Request) tab instead of remembering the previous tab.
- **Paging keys**: `ctrl+d`/`ctrl+u` page down/up (mirroring `ctrl+f`/`ctrl+b`).
- **`g`/`G`**: jump to top/bottom while keeping the selection coupled to the
  scroll position (fixed cursor handling).
- **Key remaps**:
  - `i` → toggle interactive request intercept.
  - `I` → toggle interactive response intercept.
  - `r` → prompt for a replay file name (`console.replay.prompt`).
  - `t` → run a tool on the flow.
  - `e` → edit the flow's `.req` file in Neovim.
  - Removed `d` (delete) and `D` (duplicate) bindings.
- **Quick help** updated to reflect the new bindings.
- `console.choose`/`console.choose.cmd` warn instead of erroring when there are
  no choices available.

### Terminal robustness (`master.py`)

The urwid main loop start/stop is now guarded (`_ui_start`/`_ui_stop`,
`_loop_started`) so that interrupting mitmproxy (e.g. `ctrl+c`) or spawning an
external editor no longer corrupts the terminal by leaving it in raw mode / the
alternate buffer.

## Persisted view filter (`mitmproxy/addons/view.py`)

The current view filter is persisted to `view-filter.txt` in the working
directory and restored on startup (an explicit `--view-filter` takes
precedence). `console_focus_follow` defaults to `True` here too.

## Other behavioral changes

- **Anticache enabled by default** (`mitmproxy/addons/anticache.py`):
  `anticache` now defaults to `True`, stripping headers that may cause `304 Not
  Modified` responses. (Note: the CHANGELOG/commit history also references
  disabling cache by default.)

## Tooling / project

- **Nix flake** (`flake.nix`, `flake.lock`): builds `pwnproxy` as an overridden
  `mitmproxy` package (tests disabled).
- `test.sh`: helper to run a sandboxed dev shell with a local virtualenv.
- `.gitignore`: ignores `*.req`, `*.resp`, `*.req.orig`, `*.resp.orig`,
  `view-filter.txt`, and `.box-venv/`.
- `AGENTS.md`: adds a note to run `uv sync --reinstall` if the environment
  seems broken.

## Tests

New/updated tests accompany the changes, including:

- `test/mitmproxy/addons/test_rawsave.py`
- `test/mitmproxy/addons/test_tools.py`
- `test/mitmproxy/addons/test_upstream_auth.py`
- `test/mitmproxy/addons/test_view.py`
- `test/mitmproxy/proxy/layers/http/test_http.py`
- `test/mitmproxy/proxy/test_mode_specs.py`
- `test/mitmproxy/tools/console/test_flowlist.py`
- `test/mitmproxy/tools/console/test_flowview.py`
- `test/mitmproxy/tools/console/test_master.py`
- `test/mitmproxy/tools/console/test_common.py`
