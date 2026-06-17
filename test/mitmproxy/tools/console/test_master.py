import asyncio
import threading
from unittest.mock import Mock


def test_spawn_editor(monkeypatch, console):
    text_data = "text"
    binary_data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"

    console.get_editor = Mock()
    console.get_editor.return_value = "editor"
    console.get_hex_editor = Mock()
    console.get_hex_editor.return_value = "editor"
    monkeypatch.setattr("subprocess.call", (lambda _: None))

    console.loop = Mock()
    console.loop.stop = Mock()
    console.loop.start = Mock()
    console.loop.draw_screen = Mock()

    console.spawn_editor(text_data)
    console.get_editor.assert_called_once()

    console.spawn_editor(binary_data)
    console.get_hex_editor.assert_called_once()


async def test_spawn_editor_file_nonblocking(monkeypatch, console):
    # The `e` hotkey must not block the event loop while the editor is open:
    # the editor subprocess is run in an executor and awaited, so the proxy
    # keeps running. Here we assert the loop keeps making progress while the
    # (blocking) editor call is in flight.
    console.get_editor = Mock(return_value="editor")

    editor_running = asyncio.Event()
    release_editor = threading.Event()

    def fake_call(cmd):
        # Signal that the editor "started", then block the worker thread until
        # the test allows it to finish -- mimicking a user editing a file.
        loop.call_soon_threadsafe(editor_running.set)
        release_editor.wait()

    monkeypatch.setattr("subprocess.call", fake_call)

    console._ui_stop = Mock()
    console._ui_restart = Mock()

    loop = asyncio.get_running_loop()
    console.spawn_editor_file("/tmp/some.req")

    # The event loop must remain responsive while the editor blocks.
    await asyncio.wait_for(editor_running.wait(), timeout=2)
    progressed = False
    for _ in range(3):
        await asyncio.sleep(0)
        progressed = True
    assert progressed
    console._ui_stop.assert_called_once()
    console._ui_restart.assert_not_called()  # editor still open

    # Let the editor exit and ensure the TUI is restored.
    release_editor.set()
    for _ in range(100):
        if console._ui_restart.call_count:
            break
        await asyncio.sleep(0.01)
    console._ui_restart.assert_called_once()


def test_get_hex_editor(monkeypatch, console):
    test_editor = "hexedit"
    monkeypatch.setattr("shutil.which", lambda x: x == test_editor)
    editor = console.get_hex_editor()
    assert editor == test_editor


async def test_ui_stop_robustness(monkeypatch, console):
    # urwid's MainLoop.stop() is not idempotent and assumes the loop was
    # fully started -- otherwise it raises AttributeError and leaves the
    # terminal in raw mode while the application keeps redrawing.
    # _ui_stop() must guard against that and always restore the terminal.
    console._loop_started = True
    monkeypatch.setattr(console.loop, "stop", Mock(side_effect=AttributeError))
    ui_stop = Mock()
    monkeypatch.setattr(console.ui, "stop", ui_stop)
    monkeypatch.setattr(console.ui, "_started", True)

    console._ui_stop()  # must not raise despite loop.stop() failing
    ui_stop.assert_called_once()  # terminal restored as a fallback
    assert console._loop_started is False

    # A second stop must be a no-op (no double restore, no crash).
    console._ui_stop()
    ui_stop.assert_called_once()


async def test_ui_stop_not_started(monkeypatch, console):
    # Stopping a loop that was never started must not touch it or crash.
    console._loop_started = False
    loop_stop = Mock()
    monkeypatch.setattr(console.loop, "stop", loop_stop)
    console._ui_stop()
    loop_stop.assert_not_called()
