import urwid

from mitmproxy.tools.console.searchable import Searchable

SIZE = (80, 24)


def visible_lines(box) -> list[str]:
    return [line.decode() for line in box.render(SIZE, focus=True).text]


def test_m_start_scrolls_to_top():
    box = Searchable([urwid.Text(f"line{i}") for i in range(200)])
    box.render(SIZE, focus=True)
    box.keypress(SIZE, "m_end")
    box.render(SIZE, focus=True)
    box.keypress(SIZE, "m_start")
    lines = visible_lines(box)
    assert lines[0].strip() == "line0"


def test_m_end_scrolls_to_bottom_with_many_widgets():
    box = Searchable([urwid.Text(f"line{i}") for i in range(200)])
    box.render(SIZE, focus=True)
    box.keypress(SIZE, "m_end")
    lines = visible_lines(box)
    assert lines[-1].strip() == "line199"


def test_m_end_scrolls_to_bottom_with_single_tall_widget():
    # Regression test: the response body is rendered as a single, very tall
    # urwid.Text widget. "Go to end" (G) must scroll to the bottom of that
    # widget instead of anchoring its top to the viewport.
    body = "\n".join(f"line{i}" for i in range(200))
    box = Searchable([urwid.Text(body)])
    box.render(SIZE, focus=True)
    box.keypress(SIZE, "m_end")
    lines = visible_lines(box)
    assert lines[-1].strip() == "line199"


def test_m_start_and_end_with_headers_and_tall_body():
    # Mirrors the real flow response layout: a few header lines followed by a
    # single tall body widget. Both g (top) and G (bottom) must work.
    body = "\n".join(f"body{i}" for i in range(200))
    box = Searchable([urwid.Text(f"header{i}") for i in range(3)] + [urwid.Text(body)])
    box.render(SIZE, focus=True)

    box.keypress(SIZE, "m_end")
    assert visible_lines(box)[-1].strip() == "body199"

    box.keypress(SIZE, "m_start")
    assert visible_lines(box)[0].strip() == "header0"
