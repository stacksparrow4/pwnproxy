from functools import lru_cache

import urwid

import mitmproxy.tools.console.master
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
        filename = f"{n:06d}" if n is not None else None

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
        walker = self.body
        if key == "m_start":
            self.master.commands.execute("view.focus.go 0")
            # Move the viewport to the top along with the selection.
            walker.focus_override = None
            walker.follow_bottom = False
            self.shift_focus(size, 0)
            self._invalidate()
        elif key == "m_end":
            self.master.commands.execute("view.focus.go -1")
            # Move the viewport to the bottom and keep following new flows.
            walker.focus_override = self._max_scroll_anchor(size)
            walker.follow_bottom = True
            self.shift_focus(size, 0)
            self._invalidate()
        elif key == "m_select":
            self.master.commands.execute("console.view.flow @focus")
        return urwid.ListBox.keypress(self, size, key)

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

        if walker.focus_override is not None:
            top = walker.focus_override
        else:
            # No active scroll anchor yet: continue from whatever is currently
            # shown at the top of the viewport.
            middle, top_info, _bottom = self.calculate_visible(size, focus=True)
            if middle is None:
                return
            _trim_top, fill_above = top_info
            top = fill_above[-1].position if fill_above else middle.focus_pos

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
