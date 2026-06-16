from functools import lru_cache

import urwid

import mitmproxy.tools.console.master
from mitmproxy.addons.rawsave import NUMBER_WIDTH
from mitmproxy.tools.console import common
from mitmproxy.tools.console import layoutwidget

# Number of rows scrolled per mouse-wheel notch.
SCROLL_LINES = 3


class FlowItem(urwid.WidgetWrap):
    def __init__(self, master, flow):
        self.master, self.flow = master, flow
        w = self.get_text()
        urwid.WidgetWrap.__init__(self, w)

    def get_text(self):
        cols, _ = self.master.ui.get_cols_rows()
        layout = self.master.options.console_flowlist_layout
        if layout == "list" or (layout == "default" and cols < 100):
            render_mode = common.RenderMode.LIST
        else:
            render_mode = common.RenderMode.TABLE

        rawsave = self.master.addons.get("rawsave")
        n = rawsave.flow_numbers.get(self.flow.id) if rawsave else None
        filename = f"{n:0{NUMBER_WIDTH}d}" if n is not None else None

        return common.format_flow(
            self.flow,
            render_mode=render_mode,
            focused=self.flow is self.master.view.focus.flow,
            hostheader=self.master.options.showhost,
            filename=filename,
        )

    def selectable(self):
        return True

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self.master.commands.execute("console.view.flow @focus")
            return True

    def keypress(self, size, key):
        return key


class FlowListWalker(urwid.ListWalker):
    master: "mitmproxy.tools.console.master.ConsoleMaster"

    def __init__(self, master):
        self.master = master
        # Scroll anchor: the flow index to render at the top of the viewport.
        # This is decoupled from the selected flow (``view.focus``) so that
        # mouse-wheel scrolling can move the viewport without changing the
        # selection. ``None`` means "follow the selection" (the default).
        self.focus_override: int | None = None
        # Whether the viewport is currently scrolled to the bottom. When set,
        # the viewport keeps tracking the bottom as new flows arrive (so that
        # follow mode keeps working), but only while actually scrolled there.
        self.follow_bottom: bool = False

    def positions(self, reverse=False):
        # The stub implementation of positions can go once this issue is resolved:
        # https://github.com/urwid/urwid/issues/294
        ret = range(self.master.view.get_length())
        if reverse:
            return reversed(ret)
        return ret

    def view_changed(self):
        self._modified()
        self._get.cache_clear()

    def get_focus(self):
        if self.focus_override is not None:
            length = self.master.view.get_length()
            pos = max(0, min(self.focus_override, length - 1))
            if self.master.view.inbounds(pos):
                return FlowItem(self.master, self.master.view[pos]), pos
        if not self.master.view.focus.flow:
            return None, 0
        f = FlowItem(self.master, self.master.view.focus.flow)
        return f, self.master.view.focus.index

    def set_focus(self, index):
        # Any explicit focus change (keyboard navigation, click) re-couples
        # the scroll position to the selection.
        self.focus_override = None
        self.follow_bottom = False
        if self.master.commands.execute("view.properties.inbounds %d" % index):
            self.master.view.focus.index = index
        # Recompute whether the cursor should keep following new flows. This
        # path is also taken by mouse clicks, which (unlike keyboard
        # navigation) never reach ``FlowListBox._update_follow``. Without this,
        # clicking a flow that isn't the last one would leave
        # ``view.focus_follow`` stale, so the selection would keep jumping to
        # newly arriving flows.
        length = self.master.view.get_length()
        cursor_at_bottom = length == 0 or self.master.view.focus.index == length - 1
        self.master.view.focus_follow = (
            self.master.options.console_focus_follow and cursor_at_bottom
        )

    @lru_cache(maxsize=None)
    def _get(self, pos: int) -> tuple[FlowItem | None, int | None]:
        if not self.master.view.inbounds(pos):
            return None, None
        return FlowItem(self.master, self.master.view[pos]), pos

    def get_next(self, pos):
        return self._get(pos + 1)

    def get_prev(self, pos):
        return self._get(pos - 1)


class FlowListBox(urwid.ListBox, layoutwidget.LayoutWidget):
    title = "Flows"
    keyctx = "flowlist"

    def __init__(self, master: "mitmproxy.tools.console.master.ConsoleMaster") -> None:
        self.master: "mitmproxy.tools.console.master.ConsoleMaster" = master
        super().__init__(FlowListWalker(master))
        self.master.options.subscribe(
            self.set_flowlist_layout, ["console_flowlist_layout"]
        )

    def keypress(self, size, key):
        result = self._keypress(size, key)
        # Following should only be active while the viewport is at the bottom,
        # so re-evaluate after every key (navigation may have moved us away
        # from -- or back to -- the end of the list).
        self._update_follow(size)
        return result

    def _keypress(self, size, key):
        walker = self.body
        if key == "m_start":
            self.master.commands.execute("view.focus.go 0")
            # Move the viewport to the top along with the selection. Keep the
            # selection coupled to the scroll position so that subsequent
            # keyboard navigation works as expected.
            walker.focus_override = None
            walker.follow_bottom = False
            self.set_focus_valign("top")
            self._invalidate()
        elif key == "m_end":
            self.master.commands.execute("view.focus.go -1")
            # Align the (now last) selected flow to the bottom of the viewport.
            # We keep it as the actual focus -- rather than a detached scroll
            # anchor -- so that up/down navigate from it instead of jumping.
            walker.focus_override = None
            walker.follow_bottom = False
            self.set_focus_valign("bottom")
            self._invalidate()
        elif key == "m_select":
            self.master.commands.execute("console.view.flow @focus")
        elif walker.focus_override is not None:
            # Any other key is navigation handled by urwid's ListBox (up/down,
            # page up/down, ...). urwid derives the movement from the widget
            # reported by ``get_focus()``, which while a scroll anchor is
            # active is the top-of-viewport flow rather than the selected one.
            # Re-couple the viewport to the selected flow first so that
            # navigation continues from the selection instead of jumping to
            # wherever the user scrolled to.
            walker.focus_override = None
            walker.follow_bottom = False
            index = self.master.view.focus.index
            if index is not None:
                self.change_focus(size, index)
        return urwid.ListBox.keypress(self, size, key)

    def _at_bottom(self, size) -> bool:
        # Whether the viewport is scrolled all the way to the bottom, i.e. the
        # last flow is shown at the bottom edge. This is about the *viewport*,
        # not the selection: moving the cursor up while the last flow stays
        # visible does not count as scrolling up.
        if self.master.view.get_length() == 0:
            return True
        top = self._viewport_top(size)
        if top is None:
            return True
        return top >= self._max_scroll_anchor(size)

    def _viewport_top(self, size) -> int | None:
        # The flow index currently rendered at the top of the viewport.
        walker = self.body
        if walker.focus_override is not None:
            return walker.focus_override
        middle, top_info, _bottom = self.calculate_visible(size, focus=True)
        if middle is None:
            return None
        _trim_top, fill_above = top_info
        return fill_above[-1].position if fill_above else middle.focus_pos

    def _update_follow(self, size) -> None:
        # "Following" is really two independent behaviours that we gate
        # separately:
        #
        # 1. The *selected flow* (cursor) only jumps to newly arriving flows
        #    while it is itself the last flow in the list. Moving the cursor up
        #    therefore pins the focused flow in place, even as new flows
        #    arrive.
        # 2. The *viewport* keeps tailing new flows as long as it shows the end
        #    of the list, regardless of where the cursor is.
        #
        # ``console_focus_follow`` is the user's master switch for both.
        walker = self.body
        length = self.master.view.get_length()
        user_follow = self.master.options.console_focus_follow

        index = self.master.view.focus.index
        cursor_at_bottom = length == 0 or index == length - 1
        self.master.view.focus_follow = user_follow and cursor_at_bottom

        # If the cursor has been moved up but the viewport still shows the
        # bottom, switch to a detached scroll anchor so the viewport keeps
        # tailing new flows without dragging the selection along.
        if (
            user_follow
            and walker.focus_override is None
            and not cursor_at_bottom
            and self._at_bottom(size)
        ):
            walker.focus_override = self._max_scroll_anchor(size)
            walker.follow_bottom = True
            self.shift_focus(size, 0)

    def mouse_event(self, size, event, button, col, row, focus):
        # Scroll the flow list with the mouse wheel (buttons 4/5) instead of
        # changing the selected flow, like scrolling a webpage.
        if event == "mouse press" and button in (4, 5):
            self.scroll(size, up=button == 4, lines=SCROLL_LINES)
            return True
        return super().mouse_event(size, event, button, col, row, focus)

    def scroll(self, size, up: bool, lines: int) -> None:
        # Scroll the viewport without changing the selected flow. We move the
        # walker's scroll anchor (the flow rendered at the top of the
        # viewport), which is independent of ``view.focus``. The selected flow
        # keeps its highlight and simply scrolls in and out of view.
        length = self.master.view.get_length()
        if length == 0:
            return
        walker = self.body

        # Continue from whatever is currently shown at the top of the viewport.
        top = self._viewport_top(size)
        if top is None:
            return

        max_anchor = self._max_scroll_anchor(size)
        if up:
            top = max(0, top - lines)
        else:
            # Don't scroll past the point where the last flow sits at the
            # bottom of the viewport, otherwise the rendering stops changing
            # while the anchor keeps advancing ("stored" overscroll).
            top = min(max_anchor, top + lines)

        walker.focus_override = top
        # Keep following new flows only while scrolled to the very bottom.
        walker.follow_bottom = top >= max_anchor
        self._update_follow(size)
        walker._modified()
        # Render the scroll anchor at the very top of the viewport.
        self.shift_focus(size, 0)
        self._invalidate()

    def render(self, size, focus: bool = False):
        walker = self.body
        # While scrolled to the bottom, keep the viewport pinned there so that
        # newly arriving flows remain visible (follow mode).
        if walker.follow_bottom and walker.focus_override is not None:
            walker.focus_override = self._max_scroll_anchor(size)
        self._update_follow(size)
        return super().render(size, focus)

    def _max_scroll_anchor(self, size) -> int:
        # The largest top-of-viewport flow index that still fills the screen,
        # i.e. the anchor at which the last flow is at the bottom edge.
        maxcol, maxrow = size
        walker = self.body
        total = 0
        pos = self.master.view.get_length() - 1
        while pos >= 0:
            widget, _ = walker._get(pos)
            if widget is None:
                break
            total += widget.rows((maxcol,))
            if total >= maxrow:
                return pos
            pos -= 1
        return 0

    def view_changed(self):
        self.body.view_changed()

    def set_flowlist_layout(self, *_) -> None:
        self.master.ui.clear()
