"""
An external editor (e.g. nvim) embedded *inside* the console TUI.

Historically, mitmproxy suspended the whole urwid UI and ran the editor with a
blocking ``subprocess.call``. Because the TUI and the proxy share a single
asyncio event loop, that froze the proxy until the editor exited.

Here the editor instead runs on a pseudo-terminal rendered by an
``urwid.Terminal`` widget. The pty master is watched by the asyncio event loop,
so the proxy keeps servicing connections while the editor is open, and the
flow list keeps updating in the background.

* Only one editor runs at a time. Further requests are queued (and de-duplicated
  by path); each request gets a future that resolves once *its* editor exits.
* ``ctrl ]`` (see :data:`TOGGLE_KEY`) hides the editor without closing it, so
  the rest of the UI can be used; pressing it again brings the editor back.
"""

from __future__ import annotations

import asyncio
import atexit
import collections
import contextlib
import logging
import os
import re
import shutil
import signal
import termios
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import urwid

from mitmproxy.tools.console import layoutwidget
from mitmproxy.tools.console import signals

if TYPE_CHECKING:  # pragma: no cover
    from mitmproxy.tools.console.master import ConsoleMaster

logger = logging.getLogger(__name__)

#: urwid key that hides/shows the embedded editor. It is the only key that is
#: *not* forwarded to the editor while it has focus.
TOGGLE_KEY = "ctrl ]"

#: Terminal type advertised to the editor. urwid's terminal emulator implements
#: the Linux console escape sequences (plus 256/true-colour SGR).
TERM = "linux"

ESC = "\x1b"

#: How often we poll for an exited-but-not-yet-reaped editor process.
REAP_INTERVAL = 0.1
#: Number of reaping attempts after which an editor that ignored SIGHUP is killed.
KILL_AFTER = 20


def available() -> bool:
    """Embedding needs POSIX ptys."""
    return os.name == "posix" and hasattr(os, "fork")


def translate_key(key: str, decckm: bool = False) -> str | None:
    """
    Translate an urwid key name into the bytes a terminal would send, or
    ``None`` if the key has no terminal representation.

    urwid's own ``Terminal.keypress`` writes unknown key names (``"meta x"``,
    ``"shift up"``, ...) verbatim into the pty, which types garbage into the
    editor. We handle the common cases and drop the rest.
    """
    if key.startswith("meta "):
        rest = translate_key(key[5:], decckm)
        return None if rest is None else ESC + rest
    if key.startswith("ctrl ") and len(key) == 6:
        c = key[-1]
        if c == "@" or c == " ":
            return "\x00"
        code = ord(c.upper()) - ord("A") + 1
        if 0 <= code < 32:
            return chr(code)
        return None
    if key == "ctrl space":
        return "\x00"
    if key == "shift tab":
        return f"{ESC}[Z"
    if decckm and key in urwid.vterm.KEY_TRANSLATIONS_DECCKM:
        return urwid.vterm.KEY_TRANSLATIONS_DECCKM[key]
    if key in urwid.vterm.KEY_TRANSLATIONS:
        return urwid.vterm.KEY_TRANSLATIONS[key]
    if len(key) == 1:
        return key
    return None


#: A CSI sequence urwid's ``TermCanvas.parse_csi`` understands: optional ``?``
#: private marker and ``;``-separated numeric parameters, no intermediates.
_SUPPORTED_CSI = re.compile(rb"\??[0-9;]*")

#: ESC-introduced control strings (DCS, SOS, PM, APC), terminated by ST/BEL.
_STRING_INTRODUCERS = frozenset((b"P", b"X", b"^", b"_"))

#: parsestate for "inside a control string" (urwid uses 0-3).
_STATE_STRING = 4


class EditorCanvas(urwid.vterm.TermCanvas):
    """
    ``urwid.vterm.TermCanvas`` with ECMA-48 compliant escape-sequence
    *parsing*.

    urwid's emulator aborts a CSI sequence at the first byte it doesn't
    expect and prints the rest as text. Modern editors routinely send such
    sequences (nvim sends e.g. ``CSI 2 SP q`` to set the cursor shape,
    ``CSI ? 69 $ p`` / ``CSI > 4 ; 2 m`` / ``DCS $ q m ST`` capability
    queries), which then show up as stray ``q``/``p``/``4;2m`` characters on
    screen. Here, any well-formed but unsupported sequence is swallowed.
    """

    parsestate: int
    escbuf: bytes

    def process_char(self, char: int | bytes) -> None:
        if self.parsestate == _STATE_STRING:
            if isinstance(char, int):  # pragma: no cover
                char = bytes([char])
            # A control string ends with ST (ESC + backslash) or BEL, or is cancelled.
            if char in (b"\a", b"\x18", b"\x1a", b"\x9c") or (
                self.escbuf == ESC.encode() and char == b"\\"
            ):
                self.leave_escape()
            else:
                self.escbuf = ESC.encode() if char == ESC.encode() else b""
            return
        super().process_char(char)

    def parse_escape(self, char: bytes) -> None:
        if self.parsestate == 0 and char in _STRING_INTRODUCERS:
            self.parsestate = _STATE_STRING
            self.escbuf = b""
            return
        if self.parsestate == 1 and len(char) == 1:
            b = char[0]
            if 0x20 <= b <= 0x3F:  # parameter and intermediate bytes
                self.escbuf += char
                return
            if 0x40 <= b <= 0x7E:  # final byte
                qmark = self.escbuf.startswith(b"?")
                if (
                    _SUPPORTED_CSI.fullmatch(self.escbuf)
                    and char in urwid.vterm.CSI_COMMANDS
                    and (not qmark or char in b"hl")
                ):
                    self.parse_csi(char)
                self.leave_escape()
                return
        super().parse_escape(char)


class EditorTerminal(urwid.Terminal):
    """
    ``urwid.Terminal`` with a few fixes for running an editor inside mitmproxy:

    * the executable is resolved *before* forking and the forked child does
      nothing but ``exec`` (or ``_exit``), so it can never fall back into
      mitmproxy's code if ``exec`` fails;
    * every key except :data:`TOGGLE_KEY` goes straight to the editor (no
      urwid "key grabbing" modes), with proper key translation;
    * the child is reaped without blocking the event loop; the ``exited``
      signal is emitted once that happened (``returncode`` is then set).
    """

    signals = [*urwid.Terminal.signals, "exited"]

    terminated: bool
    has_focus: bool
    term: urwid.vterm.TermCanvas | None

    def __init__(self, argv: Sequence[str], main_loop) -> None:
        executable = shutil.which(argv[0])
        if executable is None:
            raise FileNotFoundError(argv[0])
        env = dict(os.environ)
        env["TERM"] = TERM
        # We only emulate what TERM advertises.
        env.pop("COLORTERM", None)
        super().__init__(list(argv), env=env, main_loop=main_loop)
        self.escape_sequence = TOGGLE_KEY
        self.executable = executable
        self.returncode: int | None = None

    def change_focus(self, has_focus) -> None:
        """
        While focused, disable the tty's signal keys (ctrl-c, ctrl-z, ...) so
        that they reach the editor.

        urwid does this on *every* render, so from the second focused render
        on it "saves" the already-disabled keys as the originals and never
        restores ctrl-c & co. We only act on focus transitions instead.
        """
        if self.terminated:
            return
        if self.term is not None:
            self.term.has_focus = has_focus
            self.term.set_term_cursor()
        if has_focus == self.has_focus:
            return
        self.has_focus = has_focus
        term = urwid.display.common.RealTerminal()
        try:
            if has_focus:
                self.old_tios = term.tty_signal_keys()  # None if not a tty
                if self.old_tios:
                    term.tty_signal_keys(*(["undefined"] * 5))
            elif getattr(self, "old_tios", None):
                term.tty_signal_keys(*self.old_tios)
                self.old_tios = None
        except (OSError, termios.error):  # pragma: no cover
            pass

    def touch_term(self, width: int, height: int) -> None:
        if self.term is None:
            self.term = EditorCanvas(width, height, self)
        super().touch_term(width, height)

    def spawn(self) -> None:
        import pty

        argv = [os.fsencode(a) for a in self.command]
        env = {os.fsencode(k): os.fsencode(v) for k, v in self.env.items()}
        executable = os.fsencode(self.executable)
        self.pid, self.master = pty.fork()
        if self.pid == 0:  # pragma: no cover (child process)
            try:
                os.execve(executable, argv, env)
            finally:
                os._exit(127)
        atexit.register(self.terminate)

    def keypress(self, size, key: str) -> str | None:
        if self.terminated or key == TOGGLE_KEY:
            return key
        if key == "window resize":
            self.touch_term(*size)
            return None
        if key in ("begin paste", "end paste"):
            if not self.term_modes.bracketed_paste:
                return None
            data: str | None = f"{ESC}[200~" if key == "begin paste" else f"{ESC}[201~"
        else:
            data = translate_key(key, self.term_modes.keys_decckm)
        if data is None:
            return None
        if self.term:
            self.term.scroll_buffer(reset=True)
        if self.term_modes.lfnl and data == "\r":
            data += "\n"
        with contextlib.suppress(OSError):
            os.write(self.master, data.encode(self.encoding, "ignore"))
        return None

    def terminate(self) -> None:
        if self.terminated:
            return
        self.change_focus(False)  # before setting terminated, it'd be a no-op
        self.terminated = True
        atexit.unregister(self.terminate)
        if self.master is not None:
            self.remove_watch()
            with contextlib.suppress(OSError):
                os.close(self.master)
        if self.pid:
            # No-op if the editor already exited; makes it quit otherwise
            # (e.g. when mitmproxy shuts down while the editor is open).
            with contextlib.suppress(OSError):
                os.kill(self.pid, signal.SIGHUP)
            self._reap()
        else:
            self._emit("exited")

    def _reap(self, attempt: int = 0) -> None:
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:  # pragma: no cover
            pid, status = self.pid, None
        if pid == 0:
            if attempt == KILL_AFTER:
                with contextlib.suppress(OSError):
                    os.kill(self.pid, signal.SIGKILL)
            # The event loop may already be gone if we're called via atexit.
            with contextlib.suppress(RuntimeError):
                self.main_loop.alarm(REAP_INTERVAL, lambda: self._reap(attempt + 1))
            return
        if status is not None:
            self.returncode = os.waitstatus_to_exitcode(status)
        self._emit("exited")


class Session:
    def __init__(self, path: str, argv: list[str], future: asyncio.Future) -> None:
        self.path = path
        self.argv = argv
        self.future = future
        self.terminal: EditorTerminal | None = None

    @property
    def name(self) -> str:
        return Path(self.path).name


class EditorWindow(urwid.WidgetWrap, layoutwidget.LayoutWidget):
    """The window that shows the active editor session."""

    keyctx = "editor"
    title = "Editor"

    def __init__(self, master: ConsoleMaster) -> None:
        self.master = master
        super().__init__(urwid.SolidFill(" "))

    def layout_pushed(self, prev) -> None:
        s = self.master.editors.active
        if s is not None and s.terminal is not None:
            self.title = f"Editor: {s.name}  ({TOGGLE_KEY} to hide)"
            self._w = s.terminal
        else:
            self.title = "Editor"
            self._w = urwid.SolidFill(" ")

    def layout_popping(self) -> None:
        # The terminal disables the tty's signal keys (ctrl-c, ...) while it
        # has focus, and only restores them when rendered without focus. It
        # won't be rendered again once hidden, so restore them now.
        if isinstance(self._w, EditorTerminal):
            self._w.change_focus(False)


class EditorSessions:
    """Runs editor sessions inside the TUI, one at a time."""

    def __init__(self, master: ConsoleMaster) -> None:
        self.master = master
        self.active: Session | None = None
        self.queue: collections.deque[Session] = collections.deque()

    def open(self, path: str, argv: list[str]) -> asyncio.Future:
        """
        Open ``path`` using ``argv`` in the embedded terminal. Returns a
        future that resolves (with the editor's exit code, or ``None`` if the
        editor could not be started) once the editor exits.
        """
        for s in ([self.active] if self.active else []) + list(self.queue):
            if s.path == path:
                self.show()
                return s.future

        session = Session(path, argv, asyncio.get_running_loop().create_future())
        if self.active is None:
            self._start(session)
        else:
            self.queue.append(session)
            self.show()
            signals.status_message.send(
                message=f"Editor busy: {session.name} will open once "
                f"{self.active.name} is closed ({len(self.queue)} queued).",
                expire=3,
            )
        return session.future

    def _start(self, session: Session) -> None:
        try:
            session.terminal = EditorTerminal(
                session.argv, main_loop=self.master.loop.event_loop
            )
        except OSError as e:
            signals.status_message.send(
                message=f"Can't start editor {session.argv[0]!r}: {e}"
            )
            session.future.set_result(None)
            self._next()
            return
        urwid.connect_signal(
            session.terminal, "exited", lambda *_: self._closed(session)
        )
        self.active = session
        self.show()

    def _closed(self, session: Session) -> None:
        if session is not self.active:  # already cleaned up by shutdown()
            return
        self.active = None
        self._remove_windows()
        assert session.terminal is not None
        code = session.terminal.returncode
        if code:
            signals.status_message.send(
                message=f"Editor exited with status {code}.", expire=3
            )
        if not session.future.done():
            session.future.set_result(code)
        self._next()

    def _next(self) -> None:
        if self.queue and self.active is None:
            self._start(self.queue.popleft())

    def _remove_windows(self) -> None:
        w = self.master.window
        if w is None:
            return
        for stack in w.stacks:
            if "editor" in stack.stack:
                if stack.stack[-1] == "editor" and not stack.overlay:
                    stack.call("layout_popping")
                stack.stack = [n for n in stack.stack if n != "editor"]
        w.refresh()
        w.view_changed()
        w.focus_changed()

    def is_shown(self) -> bool:
        w = self.master.window
        return bool(w and w.focus_stack().stack[-1] == "editor")

    def show(self) -> None:
        if self.active is None or self.master.window is None:
            return
        if not self.is_shown():
            # The editor must only be on one stack at a time.
            self._remove_windows()
            self.master.window.push("editor")

    def hide(self) -> None:
        if self.is_shown():
            assert self.master.window
            self.master.window.pop()
            signals.status_message.send(
                message=f"Editor hidden. Press {TOGGLE_KEY} to return to it.",
                expire=3,
            )

    def toggle(self) -> None:
        if self.is_shown():
            self.hide()
        elif self.active is not None:
            self.show()
        else:
            signals.status_message.send(message="No editor running.", expire=1)

    def shutdown(self) -> None:
        """Close all editors and resolve all pending futures."""
        pending = ([self.active] if self.active else []) + list(self.queue)
        self.active = None
        self.queue.clear()
        for s in pending:
            if s.terminal is not None:
                s.terminal.terminate()
            if not s.future.done():
                s.future.set_result(None)
