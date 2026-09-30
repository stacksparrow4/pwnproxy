import asyncio
import os
import signal
from unittest.mock import Mock

import pytest
import urwid

from mitmproxy import pwnproxy_config
from mitmproxy.tools.console import editor
from mitmproxy.tools.console import quickhelp
from mitmproxy.tools.console import signals

pytestmark = pytest.mark.skipif(not editor.available(), reason="requires ptys")

SIZE = (40, 5)


def urwid_loop():
    return urwid.AsyncioEventLoop(loop=asyncio.get_running_loop())


def text(canvas, row=0) -> str:
    return b"".join(c[2] for c in list(canvas.content())[row]).decode().rstrip()


def screen(t: editor.EditorTerminal) -> str:
    return "\n".join(text(t.term, i) for i in range(t.term.height))


def wait_exited(t: editor.EditorTerminal, timeout=5):
    """Connect to the ``exited`` signal *now*, return an awaitable for it."""
    done = asyncio.Event()
    urwid.connect_signal(t, "exited", lambda *_: done.set())
    return asyncio.wait_for(done.wait(), timeout)


async def eventually(predicate, timeout=5):
    for _ in range(int(timeout / 0.01)):
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met")


def test_available():
    assert editor.available() is True


@pytest.mark.parametrize(
    "key,decckm,expected",
    [
        ("a", False, "a"),
        ("enter", False, "\r"),
        ("esc", False, "\x1b"),
        ("up", False, "\x1b[A"),
        ("up", True, "\x1bOA"),
        ("ctrl a", False, "\x01"),
        ("ctrl A", False, "\x01"),
        ("ctrl ]", False, "\x1d"),
        ("ctrl @", False, "\x00"),
        ("ctrl space", False, "\x00"),
        ("ctrl ~", False, None),
        ("meta x", False, "\x1bx"),
        ("meta up", False, "\x1b\x1b[A"),
        ("meta shift up", False, None),
        ("shift tab", False, "\x1b[Z"),
        ("shift up", False, None),
        ("mouse press", False, None),
    ],
)
def test_translate_key(key, decckm, expected):
    assert editor.translate_key(key, decckm) == expected


def test_canvas_swallows_unsupported_sequences():
    t = editor.EditorTerminal(["sh"], main_loop=None)
    c = editor.EditorCanvas(20, 3, t)
    c.addstr(
        b"\x1b[2 q"  # DECSCUSR (intermediate byte)
        b"\x1b[?69$p"  # DECRQM
        b"\x1b[>4;2m"  # xterm modifyOtherKeys
        b"\x1b[4:3m"  # colon sub-parameters
        b"\x1b[?1u"  # private sequence urwid can't handle
        b"\x1bP$qm\x1b\\"  # DCS terminated by ST
        b"\x1b_apc\x07"  # APC terminated by BEL
        b"\x1bXsos\x18"  # SOS cancelled
        b"A"
        b"\x1b[?25l"  # supported private mode
        b"\x1b[1;31mB"  # supported SGR
        b"\x1b[Hc"  # supported cursor movement
    )
    assert text(c) == "cB"
    assert t.term_modes.visible_cursor is False
    row = list(c.content())[0]
    assert "red" in row[1][0].foreground


def test_canvas_mouse_modes():
    t = editor.EditorTerminal(["sh"], main_loop=None)
    c = editor.EditorCanvas(20, 3, t)
    assert t.mouse_modes == editor.MouseModes()
    c.addstr(b"\x1b[?1002h\x1b[?1006h")  # what nvim sends
    assert t.mouse_modes == editor.MouseModes(1002, 1006)
    c.addstr(b"\x1b[?1000h\x1b[?1015h")
    assert t.mouse_modes == editor.MouseModes(1000, 1015)
    c.addstr(b"\x1b[?1000l\x1b[?1015l\x1b[?25l")
    assert t.mouse_modes == editor.MouseModes()
    assert t.term_modes.visible_cursor is False  # other modes still work
    c.addstr(b"\x1b[?1003;1005h\x1bcx")  # RIS resets mouse modes
    assert t.mouse_modes == editor.MouseModes()


SGR = editor.MouseModes(editor.MOUSE_BUTTON_EVENT, editor.MOUSE_SGR)


@pytest.mark.parametrize(
    "modes,event,button,expected",
    [
        (editor.MouseModes(), "mouse press", 1, None),
        (SGR, "mouse press", 1, b"\x1b[<0;3;5M"),
        (SGR, "mouse press", 3, b"\x1b[<2;3;5M"),
        (SGR, "mouse drag", 1, b"\x1b[<32;3;5M"),
        (SGR, "mouse release", 1, b"\x1b[<0;3;5m"),
        (SGR, "mouse release", 0, b"\x1b[<3;3;5m"),
        (SGR, "mouse press", 4, b"\x1b[<64;3;5M"),
        (SGR, "mouse press", 5, b"\x1b[<65;3;5M"),
        (SGR, "mouse release", 4, None),
        (SGR, "shift ctrl mouse press", 1, b"\x1b[<20;3;5M"),
        (SGR, "meta mouse press", 1, b"\x1b[<8;3;5M"),
        (SGR, "mouse press", 0, None),
        (SGR, "mouse press", 8, None),
        (SGR, "double mouse click", 1, None),
        (SGR, "press", 1, None),
        (SGR, "triple mouse press", 1, b"\x1b[<0;3;5M"),
        (editor.MouseModes(1000), "mouse press", 1, b"\x1b[M #%"),
        (editor.MouseModes(1000), "mouse release", 1, b"\x1b[M##%"),
        (editor.MouseModes(1000), "mouse drag", 1, None),
        (editor.MouseModes(1003), "mouse drag", 2, b"\x1b[MA#%"),
        (editor.MouseModes(9), "ctrl mouse press", 1, b"\x1b[M #%"),
        (editor.MouseModes(9), "mouse release", 1, None),
        (editor.MouseModes(1000, 1015), "mouse release", 1, b"\x1b[35;3;5M"),
        (editor.MouseModes(1000, 1005), "mouse press", 2, b"\x1b[M!#%"),
    ],
)
def test_encode_mouse(modes, event, button, expected):
    assert editor.encode_mouse(modes, event, button, 2, 4) == expected


def test_encode_mouse_large_coordinates():
    legacy = editor.MouseModes(1000)
    assert editor.encode_mouse(legacy, "mouse press", 1, 222, 0) == b"\x1b[M \xff!"
    assert editor.encode_mouse(legacy, "mouse press", 1, 223, 0) is None
    utf8 = editor.MouseModes(1000, 1005)
    assert (
        editor.encode_mouse(utf8, "mouse press", 1, 300, 0)
        == ("\x1b[M " + chr(333) + "!").encode()
    )
    assert editor.encode_mouse(utf8, "mouse press", 1, 2100, 0) is None
    assert editor.encode_mouse(SGR, "mouse press", 1, 2100, 0) == b"\x1b[<0;2101;1M"


async def test_terminal_mouse_event():
    # The child enables SGR mouse tracking, then echoes what it receives.
    t = editor.EditorTerminal(
        [
            "sh",
            "-c",
            r"stty raw -echo; printf '\033[?1002h\033[?1006hready\r\n';"
            r" dd bs=1 count=18 2>/dev/null | od -An -c | tr -d ' \n'; sleep 30",
        ],
        main_loop=urwid_loop(),
    )
    assert t.mouse_event(SIZE, "mouse press", 1, 0, 0, True) is False  # no pty yet
    t.render(SIZE, focus=True)
    await eventually(lambda: "ready" in screen(t))
    assert t.mouse_modes == SGR
    assert t.mouse_event(SIZE, "mouse press", 1, 2, 1, True) is True
    assert t.mouse_event(SIZE, "mouse release", 0, 2, 1, True) is True
    assert t.mouse_event(SIZE, "double mouse click", 1, 2, 1, True) is True
    await eventually(lambda: r"033[<0;3;2M033[<0;3;2m" in screen(t).replace("\\", ""))
    t.terminate()
    await wait_exited(t)
    assert t.mouse_event(SIZE, "mouse press", 1, 0, 0, True) is False


async def test_terminal_mouse_untracked_wheel():
    t = editor.EditorTerminal(
        [
            "sh",
            "-c",
            "stty raw -echo; echo ready;"
            " dd bs=1 count=6 2>/dev/null | od -An -c | tr -d ' \\n'; sleep 30",
        ],
        main_loop=urwid_loop(),
    )
    t.render(SIZE, focus=True)
    await eventually(lambda: "ready" in screen(t))
    # Without mouse tracking the wheel becomes cursor keys, the rest is ignored.
    assert t.mouse_event(SIZE, "mouse press", 4, 0, 0, True) is True
    assert t.mouse_event(SIZE, "mouse press", 5, 0, 0, True) is True
    assert t.mouse_event(SIZE, "mouse press", 1, 0, 0, True) is False
    assert t.mouse_event(SIZE, "mouse drag", 1, 0, 0, True) is False
    await eventually(lambda: "033[A033[B" in screen(t))
    t.terminate()
    await wait_exited(t)


def test_terminal_missing_executable():
    with pytest.raises(FileNotFoundError):
        editor.EditorTerminal(["mitmproxy-no-such-editor"], main_loop=None)


def test_terminal_env():
    os.environ["COLORTERM"] = "truecolor"
    try:
        t = editor.EditorTerminal(["sh"], main_loop=None)
    finally:
        del os.environ["COLORTERM"]
    assert t.env["TERM"] == editor.TERM
    assert "COLORTERM" not in t.env


async def test_terminal_lifecycle():
    t = editor.EditorTerminal(
        ["sh", "-c", "read x; echo got:$x; read y; exit 3"], main_loop=urwid_loop()
    )
    t.render(SIZE, focus=True)
    assert t.pid

    # Keys that must not end up in the editor.
    assert t.keypress(SIZE, editor.TOGGLE_KEY) == editor.TOGGLE_KEY
    assert t.keypress(SIZE, "shift up") is None
    assert t.keypress(SIZE, "begin paste") is None  # no bracketed paste mode
    assert t.keypress(SIZE, "window resize") is None

    for k in "hi":
        assert t.keypress(SIZE, k) is None
    t.keypress(SIZE, "enter")
    await eventually(lambda: "got:hi" in screen(t))

    t.term_modes.bracketed_paste = True
    t.keypress(SIZE, "begin paste")
    t.keypress(SIZE, "end paste")
    t.term_modes.lfnl = True
    t.keypress(SIZE, "enter")

    await wait_exited(t)
    assert t.returncode == 3
    assert t.terminated
    assert t.keypress(SIZE, "a") == "a"
    t.terminate()  # idempotent


async def test_terminate_running_editor():
    t = editor.EditorTerminal(["sleep", "30"], main_loop=urwid_loop())
    t.render(SIZE)
    exited = wait_exited(t)
    t.terminate()
    await exited
    assert t.returncode == -signal.SIGHUP


async def test_terminate_kills_stubborn_editor(monkeypatch):
    monkeypatch.setattr(editor, "KILL_AFTER", 1)
    monkeypatch.setattr(editor, "REAP_INTERVAL", 0.01)
    t = editor.EditorTerminal(
        ["sh", "-c", "trap '' HUP; echo ready; while :; do sleep 1; done"],
        main_loop=urwid_loop(),
    )
    t.render(SIZE)
    await eventually(lambda: "ready" in screen(t))
    exited = wait_exited(t)
    t.terminate()
    await exited
    assert t.returncode == -signal.SIGKILL


async def test_terminate_never_spawned():
    t = editor.EditorTerminal(["sh"], main_loop=urwid_loop())
    exited = wait_exited(t)
    t.terminate()
    await exited
    assert t.returncode is None


def test_change_focus_only_on_transitions(monkeypatch):
    calls = []

    def tty_signal_keys(self, *args):
        calls.append(args)
        return ("orig",) if not args else None

    monkeypatch.setattr(
        urwid.display.common.RealTerminal, "tty_signal_keys", tty_signal_keys
    )
    t = editor.EditorTerminal(["sh"], main_loop=None)
    t.change_focus(True)
    t.change_focus(True)  # e.g. a second render: must not re-save the keys
    assert calls == [(), ("undefined",) * 5]
    t.change_focus(False)
    t.change_focus(False)
    assert calls[-1] == ("orig",)
    assert len(calls) == 3


def test_change_focus_not_a_tty():
    # stdin is not a tty under pytest: must not raise.
    t = editor.EditorTerminal(["sh"], main_loop=None)
    t.change_focus(True)
    t.change_focus(False)


def test_quickhelp():
    qh = quickhelp.make(editor.EditorWindow, None, False)
    assert qh.top_label.startswith("Editor:")
    assert list(qh.top_items) == ["Hide"]
    assert qh.bottom_items == {}


# Tests using the full console.


def use_editor(monkeypatch, console, script):
    """Make `script` (a shell snippet) the configured editor."""
    monkeypatch.setattr(console, "get_editor", lambda: f"sh -c '{script}'")


class Messages(list):
    def __init__(self):
        super().__init__()
        # signals only keep a weak reference to their receivers.
        signals.status_message.connect(self.receive)

    def receive(self, message, **_):
        self.append(str(message))


def messages(monkeypatch) -> list[str]:
    return Messages()


def top(console) -> str:
    return console.window.focus_stack().stack[-1]


async def render_until_spawned(console):
    console.window.render((80, 24), True)
    await eventually(lambda: console.editors.active.terminal.pid)


async def test_open_and_close(monkeypatch, console, tmp_path):
    use_editor(monkeypatch, console, "read x")
    path = str(tmp_path / "000001.req")
    fut = console.spawn_editor_file(path)
    assert isinstance(fut, asyncio.Future)
    assert top(console) == "editor"
    assert "000001.req" in console.window.focus_stack().top_window().title
    await render_until_spawned(console)
    assert any("editor" in str(x) for x in console.window.statusbar.get_status())

    console.type("<enter>")
    assert await asyncio.wait_for(fut, 5) == 0
    assert console.editors.active is None
    assert top(console) == "flowlist"
    assert console.window.focus_stack().top_window().title != "Editor"


async def test_queue_and_dedupe(monkeypatch, console, tmp_path):
    msgs = messages(monkeypatch)
    use_editor(monkeypatch, console, 'read x; exit "$x"')
    a, b = str(tmp_path / "a.req"), str(tmp_path / "b.req")
    fa = console.spawn_editor_file(a)
    assert console.spawn_editor_file(a) is fa
    fb = console.spawn_editor_file(b)
    assert console.spawn_editor_file(b) is fb
    assert [s.path for s in console.editors.queue] == [b]
    assert any("b.req will open once a.req is closed" in m for m in msgs)
    assert any("+1" in str(x) for x in console.window.statusbar.get_status())

    await render_until_spawned(console)
    console.type("0<enter>")
    assert await asyncio.wait_for(fa, 5) == 0

    # b starts automatically once a is closed.
    assert console.editors.active.path == b
    assert top(console) == "editor"
    await render_until_spawned(console)
    console.type("5<enter>")
    assert await asyncio.wait_for(fb, 5) == 5
    assert any("exited with status 5" in m for m in msgs)
    assert console.editors.active is None


async def test_toggle(monkeypatch, console, tmp_path):
    msgs = messages(monkeypatch)
    console.editors.toggle()
    assert msgs[-1] == "No editor running."
    console.editors.hide()  # no-op

    use_editor(monkeypatch, console, "read x")
    fut = console.spawn_editor_file(str(tmp_path / "x.req"))
    await render_until_spawned(console)

    console.type("<ctrl ]>")  # the key goes through the editor to the keymap
    assert top(console) == "flowlist"
    assert "hidden" in msgs[-1]
    console.editors.show()
    assert top(console) == "editor"
    console.editors.show()  # already shown: no-op
    assert console.window.focus_stack().stack.count("editor") == 1
    console.type("<ctrl ]>")
    console.type("<ctrl ]>")
    assert top(console) == "editor"

    # Closing the editor while hidden works, too.
    console.editors.hide()
    console.editors.active.terminal.keypress(SIZE, "enter")
    assert await asyncio.wait_for(fut, 5) == 0
    assert top(console) == "flowlist"


async def test_moves_between_panes(monkeypatch, console, tmp_path):
    console.options.console_layout = "horizontal"
    use_editor(monkeypatch, console, "read x")
    fut = console.spawn_editor_file(str(tmp_path / "x.req"))
    assert console.window.stacks[0].stack[-1] == "editor"
    console.window.switch()
    console.editors.show()
    assert "editor" not in console.window.stacks[0].stack
    assert console.window.stacks[1].stack[-1] == "editor"
    await render_until_spawned(console)
    console.type("<enter>")
    assert await asyncio.wait_for(fut, 5) == 0
    assert "editor" not in console.window.stacks[1].stack


async def test_start_failure(monkeypatch, console, tmp_path):
    msgs = messages(monkeypatch)
    monkeypatch.setattr(console, "get_editor", lambda: "mitmproxy-no-such-editor")
    fut = console.spawn_editor_file(str(tmp_path / "x.req"))
    assert fut.result() is None
    assert "Can't start editor" in msgs[-1]
    assert console.editors.active is None
    assert top(console) == "flowlist"


async def test_start_failure_starts_next(monkeypatch, console, tmp_path):
    use_editor(monkeypatch, console, "read x")
    fa = console.spawn_editor_file(str(tmp_path / "a.req"))
    monkeypatch.setattr(console, "get_editor", lambda: "mitmproxy-no-such-editor")
    fb = console.spawn_editor_file(str(tmp_path / "b.req"))
    use_editor(monkeypatch, console, "exit 0")
    fc = console.spawn_editor_file(str(tmp_path / "c.req"))

    await render_until_spawned(console)
    console.type("<enter>")
    await asyncio.wait_for(fa, 5)
    assert fb.result() is None  # failed to start, c is started instead
    await render_until_spawned(console)
    assert await asyncio.wait_for(fc, 5) == 0


async def test_shutdown(monkeypatch, console, tmp_path):
    use_editor(monkeypatch, console, "read x")
    fa = console.spawn_editor_file(str(tmp_path / "a.req"))
    fb = console.spawn_editor_file(str(tmp_path / "b.req"))
    await render_until_spawned(console)
    term = console.editors.active.terminal
    console.editors.shutdown()
    assert fa.result() is None
    assert fb.result() is None
    assert console.editors.active is None
    assert term.terminated
    await eventually(lambda: term.returncode is not None)


async def test_flush(monkeypatch, console, tmp_path):
    # flush() releases the active editor and every queued one, but leaves the
    # session manager usable afterwards (unlike shutdown()).
    use_editor(monkeypatch, console, "read x")
    fa = console.spawn_editor_file(str(tmp_path / "a.req"))
    fb = console.spawn_editor_file(str(tmp_path / "b.req"))
    await render_until_spawned(console)
    term = console.editors.active.terminal

    console.flush_editor_queue()
    assert fa.result() is None
    assert fb.result() is None
    assert console.editors.active is None
    assert not console.editors.queue
    assert term.terminated
    assert top(console) != "editor"
    await eventually(lambda: term.returncode is not None)

    # still usable: a new editor can be opened.
    fc = console.spawn_editor_file(str(tmp_path / "c.req"))
    await render_until_spawned(console)
    console.type("<enter>")
    assert await asyncio.wait_for(fc, 5) == 0


async def test_no_window(console, tmp_path):
    w = console.window
    console.window = None
    try:
        console.editors._remove_windows()
        console.editors.show()
        assert not console.editors.is_shown()
    finally:
        console.window = w


async def test_blocking_fallback(monkeypatch, console, tmp_path):
    monkeypatch.setattr(pwnproxy_config, "embedded_editor", lambda: False)
    call = Mock()
    monkeypatch.setattr("subprocess.call", call)
    console.loop = Mock()
    assert console.spawn_editor_file(str(tmp_path / "x.req")) is None
    call.assert_called_once()


async def test_blocking_fallback_error(monkeypatch, console, tmp_path):
    msgs = messages(monkeypatch)
    monkeypatch.setattr(pwnproxy_config, "embedded_editor", lambda: False)
    monkeypatch.setattr("subprocess.call", Mock(side_effect=OSError))
    console.loop = Mock()
    assert console.spawn_editor_file(str(tmp_path / "x.req")) is None
    assert "Can't start editor" in msgs[-1]


async def test_window_without_session(console):
    console.window.push("editor")
    w = console.window.focus_stack().top_window()
    assert w.title == "Editor"
    assert isinstance(w._w, urwid.SolidFill)
    console.window.render((80, 24), True)
    console.window.pop()
    assert top(console) == "flowlist"


def test_screen_decodes_ctrl_h():
    from mitmproxy.tools.console import window

    s = window.Screen()
    keys, raw = s.parse_input(None, None, [8, 127, 12, 104])
    assert keys == ["ctrl h", "backspace", "ctrl l", "h"]
    # urwid's global table is left untouched.
    assert urwid.display.escape._keyconv[8] == "backspace"


async def test_ctrl_h_reaches_editor(monkeypatch, console, tmp_path):
    use_editor(monkeypatch, console, "read x")
    fut = console.spawn_editor_file(str(tmp_path / "x.req"))
    await render_until_spawned(console)
    term = console.editors.active.terminal
    keys = []
    monkeypatch.setattr(term, "keypress", lambda size, k: keys.append(k))
    console.window.keypress((80, 24), "ctrl h")
    assert keys == ["ctrl h"]
    assert editor.translate_key("ctrl h") == "\x08"

    # With the command prompt focused, ctrl h is backspace again.
    console.window.focus_position = "footer"
    console.window.keypress((80, 24), "ctrl h")
    assert keys == ["ctrl h"]
    console.window.focus_position = "body"
    monkeypatch.undo()
    console.editors.shutdown()
    await asyncio.wait_for(fut, 5)


async def test_ctrl_h_is_backspace_elsewhere(console):
    ab = console.window.statusbar.ab
    ab.sig_prompt("Test", "xy", lambda x: None)
    console.window.keypress((80, 24), "ctrl h")
    assert ab.top._w.get_edit_text() == "x"
