import urwid


class Tab(urwid.WidgetWrap):
    def __init__(self, offset, content, attr, onclick):
        """
        onclick is called on click with the tab offset as argument
        """
        p = urwid.Text(content, align="center")
        p = urwid.Padding(p, align="center", width=("relative", 100))
        p = urwid.AttrMap(p, attr)
        urwid.WidgetWrap.__init__(self, p)
        self.offset = offset
        self.onclick = onclick

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self.onclick(self.offset)
            return True


class Tabs(urwid.WidgetWrap):
    def __init__(self, tabs, tab_offset=0):
        super().__init__(urwid.Pile([]))
        self.tab_offset = tab_offset
        self.tabs = tabs
        # The tab whose body is currently rendered. Used to decide whether a
        # show() call re-renders the same tab (in which case we preserve the
        # scroll position) or switches to a different one.
        self._shown_tab: int | None = None
        self.show()

    def change_tab(self, offset):
        self.tab_offset = offset
        self.show()

    def keypress(self, size, key):
        n = len(self.tabs)
        if key == "m_next":
            self.change_tab((self.tab_offset + 1) % n)
        elif key == "m_prev":
            self.change_tab((self.tab_offset - 1) % n)
        elif key == "right":
            self.change_tab((self.tab_offset + 1) % n)
        elif key == "left":
            self.change_tab((self.tab_offset - 1) % n)
        return self._w.keypress(size, key)

    def show(self):
        if not self.tabs:
            return

        current_tab = self.tab_offset % len(self.tabs)

        # When we re-render the *same* tab (e.g. because the underlying flow
        # updated while the user was scrolling), rebuilding the body widget
        # from scratch would reset the viewport to the top. Capture the
        # current scroll position so we can restore it on the new body.
        saved_scroll = None
        if self._shown_tab == current_tab and isinstance(self._w, urwid.Frame):
            old_body = self._w.body
            if isinstance(old_body, urwid.ListBox):
                try:
                    saved_scroll = (
                        old_body.get_focus()[1],
                        old_body.offset_rows,
                    )
                except Exception:
                    saved_scroll = None

        headers = []
        for i in range(len(self.tabs)):
            txt = self.tabs[i][0]()
            if i == current_tab:
                headers.append(Tab(i, txt, "heading", self.change_tab))
            else:
                headers.append(Tab(i, txt, "heading_inactive", self.change_tab))
        headers = urwid.Columns(headers, dividechars=1)
        self._w = urwid.Frame(body=self.tabs[current_tab][1](), header=headers)
        self._w.focus_position = "body"
        self._shown_tab = current_tab

        if saved_scroll is not None:
            self._restore_scroll(*saved_scroll)

    def _restore_scroll(self, position, offset_rows) -> None:
        body = self._w.body
        if not isinstance(body, urwid.ListBox):
            return
        try:
            length = len(body.body)
        except Exception:
            return
        if not length or position is None or not (0 <= position < length):
            return
        # Restore both the focused element and its vertical offset so that the
        # viewport ends up exactly where it was before the rebuild. We set the
        # walker focus directly (instead of ListBox.set_focus) to avoid
        # scheduling a pending re-alignment that would discard offset_rows on
        # the next render.
        body.body.set_focus(position)
        body.offset_rows = offset_rows
        body.set_focus_pending = None
        body.set_focus_valign_pending = None
