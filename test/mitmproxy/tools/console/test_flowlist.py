from mitmproxy.test import tflow
from mitmproxy.tools.console.flowlist import FlowListBox


def add_flows(console, n):
    flows = [tflow.tflow() for _ in range(n)]
    console.view.add(flows)
    return flows


def flowlist(console) -> FlowListBox:
    return FlowListBox(console)


def top_pos(box, size):
    middle, top, _bottom = box.calculate_visible(size, focus=True)
    _trim_top, fill_above = top
    return fill_above[-1].position if fill_above else middle.focus_pos


async def test_scroll_does_not_change_selection(console):
    console.options.console_focus_follow = False
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)

    console.view.focus.index = 25
    box.render(size, focus=True)

    # Scrolling down moves the viewport but keeps the selected flow.
    box.scroll(size, up=False, lines=10)
    box.render(size, focus=True)
    assert console.view.focus.index == 25
    assert top_pos(box, size) == 35

    # Scrolling back up does not change the selection either.
    box.scroll(size, up=True, lines=5)
    box.render(size, focus=True)
    assert console.view.focus.index == 25
    assert top_pos(box, size) == 30


async def test_scroll_clamps_at_edges(console):
    console.options.console_focus_follow = False
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    box.render(size, focus=True)

    # Cannot scroll above the first flow.
    box.scroll(size, up=True, lines=10)
    box.render(size, focus=True)
    assert top_pos(box, size) == 0

    # Cannot scroll past the point where the last flow is at the bottom edge,
    # so no "overscroll" is stored: scrolling up once immediately moves back.
    box.scroll(size, up=False, lines=1000)
    box.render(size, focus=True)
    max_anchor = box._max_scroll_anchor(size)
    assert 0 < max_anchor < 49
    assert box.body.focus_override == max_anchor

    box.scroll(size, up=True, lines=1)
    box.render(size, focus=True)
    assert box.body.focus_override == max_anchor - 1


async def test_keyboard_navigation_recouples_selection(console):
    console.options.console_focus_follow = False
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    box.render(size, focus=True)

    box.scroll(size, up=False, lines=10)
    box.render(size, focus=True)
    assert box.body.focus_override is not None

    # An explicit focus change clears the scroll anchor.
    box.keypress(size, "down")
    assert box.body.focus_override is None


async def test_mouse_wheel_scrolls(console):
    console.options.console_focus_follow = False
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    console.view.focus.index = 25
    box.render(size, focus=True)

    # A wheel-down press (button 5) is handled and scrolls without changing
    # the selected flow.
    handled = box.mouse_event(size, "mouse press", 5, 0, 0, True)
    assert handled
    box.render(size, focus=True)
    assert console.view.focus.index == 25
    assert box.body.focus_override is not None
