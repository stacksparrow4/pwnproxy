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


def bottom_pos(box, size):
    middle, _top, bottom = box.calculate_visible(size, focus=True)
    _trim_bottom, fill_below = bottom
    return fill_below[-1].position if fill_below else middle.focus_pos


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

    # Select a flow near the top, then scroll far enough that it leaves view.
    console.view.focus.index = 5
    box.render(size, focus=True)
    box.scroll(size, up=False, lines=30)
    box.render(size, focus=True)
    assert box.body.focus_override is not None

    # An explicit focus change clears the scroll anchor and navigation
    # continues from the selected flow (5 -> 6) rather than jumping to the
    # scroll anchor.
    box.keypress(size, "down")
    assert box.body.focus_override is None
    assert console.view.focus.index == 6


async def test_focused_flow_does_not_follow_once_cursor_leaves_bottom(console):
    # The selected flow must only jump to newly arriving flows while it is
    # itself the last flow. Moving the cursor up pins the focused flow in
    # place, even though the viewport keeps tailing new flows.
    console.options.console_focus_follow = True
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    box.render(size, focus=True)

    # We start with the last flow selected, so the selection follows.
    assert console.view.focus.index == 49
    assert console.view.focus_follow

    # Moving the cursor up stops the selection from following...
    box.keypress(size, "up")
    box.render(size, focus=True)
    focused_flow = console.view.focus.flow
    assert console.view.focus.index == 48
    assert not console.view.focus_follow

    # ...but the viewport keeps tailing while it is still at the bottom.
    assert box.body.follow_bottom
    bottom_before = bottom_pos(box, size)
    add_flows(console, 5)
    box.render(size, focus=True)
    # The focused flow stays the same flow (it does not jump to the newest)...
    assert console.view.focus.flow is focused_flow
    assert console.view.focus.index == 48
    # ...while the viewport followed the new flows downward.
    assert bottom_pos(box, size) > bottom_before

    # Returning the cursor to the bottom resumes following.
    box.keypress(size, "m_end")
    box.render(size, focus=True)
    assert console.view.focus_follow
    add_flows(console, 5)
    box.render(size, focus=True)
    assert console.view.focus.index == console.view.get_length() - 1


async def test_viewport_tailing_pauses_when_scrolled_up_with_keyboard(console):
    # Scrolling the viewport up with the keyboard (cursor pushed past the top
    # of the screen) pauses tailing entirely, like the mouse wheel does.
    console.options.console_focus_follow = True
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    box.render(size, focus=True)
    bottom_top = top_pos(box, size)

    # Move the cursor up far enough to scroll the viewport off the bottom.
    for _ in range(40):
        box.keypress(size, "up")
    box.render(size, focus=True)
    assert top_pos(box, size) < bottom_top
    assert not box.body.follow_bottom
    assert not console.view.focus_follow

    # New flows must move neither the selection nor the viewport.
    top_before = top_pos(box, size)
    selection_before = console.view.focus.index
    add_flows(console, 10)
    box.render(size, focus=True)
    assert top_pos(box, size) == top_before
    assert console.view.focus.index == selection_before


async def test_follows_new_flows_when_scrolled_to_bottom(console):
    console.options.console_focus_follow = False
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    box.render(size, focus=True)

    # Scroll all the way to the bottom.
    box.scroll(size, up=False, lines=1000)
    box.render(size, focus=True)
    assert box.body.follow_bottom
    anchor = box.body.focus_override

    # New flows arriving keep the viewport pinned to the bottom.
    add_flows(console, 10)
    box.render(size, focus=True)
    assert box.body.focus_override == box._max_scroll_anchor(size)
    assert box.body.focus_override > anchor


async def test_does_not_follow_when_scrolled_up(console):
    console.options.console_focus_follow = False
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    box.render(size, focus=True)

    # Scroll to the bottom, then back up a bit.
    box.scroll(size, up=False, lines=1000)
    box.scroll(size, up=True, lines=5)
    box.render(size, focus=True)
    assert not box.body.follow_bottom
    anchor = box.body.focus_override

    # New flows must not move the viewport while scrolled up.
    add_flows(console, 10)
    box.render(size, focus=True)
    assert box.body.focus_override == anchor


async def test_g_and_G_move_viewport(console):
    console.options.console_focus_follow = False
    add_flows(console, 50)
    size = (80, 24)
    box = flowlist(console)
    box.render(size, focus=True)

    # Scroll into the middle of the list.
    box.scroll(size, up=False, lines=15)
    box.render(size, focus=True)
    assert box.body.focus_override not in (None, 0)

    # G: jump selection and viewport to the bottom, last flow at the bottom.
    box.keypress(size, "m_end")
    box.render(size, focus=True)
    assert console.view.focus.index == 49
    assert box.body.focus_override is None
    assert top_pos(box, size) == box._max_scroll_anchor(size)

    # The selection stays coupled, so up/down navigate from the last flow
    # rather than jumping elsewhere.
    box.keypress(size, "up")
    box.render(size, focus=True)
    assert console.view.focus.index == 48

    # g: jump selection and viewport back to the top.
    box.keypress(size, "m_start")
    box.render(size, focus=True)
    assert console.view.focus.index == 0
    assert box.body.focus_override is None
    assert not box.body.follow_bottom
    assert top_pos(box, size) == 0


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
