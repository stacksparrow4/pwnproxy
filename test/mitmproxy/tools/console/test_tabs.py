import urwid

from mitmproxy.tools.console import tabs
from mitmproxy.tools.console.searchable import Searchable

SIZE = (80, 24)


def make_tabs() -> tabs.Tabs:
    def body_a():
        return Searchable([urwid.Text(f"a{i}") for i in range(200)])

    def body_b():
        return Searchable([urwid.Text(f"b{i}") for i in range(200)])

    return tabs.Tabs([(lambda: "A", body_a), (lambda: "B", body_b)])


def top_pos(box) -> int:
    mid, top, _bottom = box.calculate_visible(SIZE, focus=True)
    _trim_top, fill_above = top
    return fill_above[-1].position if fill_above else mid.focus_pos


def test_show_preserves_scroll_on_same_tab():
    # Re-rendering the same tab (e.g. because the underlying flow updated while
    # the user was scrolling) must not reset the viewport to the top.
    t = make_tabs()
    body = t._w.body
    body.render(SIZE, focus=True)
    body.keypress(SIZE, "page down")
    body.keypress(SIZE, "page down")
    body.render(SIZE, focus=True)
    scrolled = top_pos(body)
    assert scrolled > 0

    t.show()
    new_body = t._w.body
    new_body.render(SIZE, focus=True)
    assert top_pos(new_body) == scrolled


def test_change_tab_resets_scroll():
    # Switching to a different tab shows fresh content from the top.
    t = make_tabs()
    body = t._w.body
    body.render(SIZE, focus=True)
    body.keypress(SIZE, "page down")
    body.keypress(SIZE, "page down")
    body.render(SIZE, focus=True)
    assert top_pos(body) > 0

    t.change_tab(1)
    new_body = t._w.body
    new_body.render(SIZE, focus=True)
    assert top_pos(new_body) == 0


def test_returning_to_tab_resets_scroll():
    # Leaving a tab and coming back is treated as fresh content, so it starts
    # from the top rather than restoring a stale scroll position.
    t = make_tabs()
    body = t._w.body
    body.render(SIZE, focus=True)
    body.keypress(SIZE, "page down")
    body.render(SIZE, focus=True)
    assert top_pos(body) > 0

    t.change_tab(1)
    t.change_tab(0)
    new_body = t._w.body
    new_body.render(SIZE, focus=True)
    assert top_pos(new_body) == 0
