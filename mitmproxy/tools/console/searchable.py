import urwid

from mitmproxy.tools.console import signals


class Highlight(urwid.AttrMap):
    def __init__(self, t):
        urwid.AttrMap.__init__(
            self,
            urwid.Text(t.text),
            "focusfield",
        )
        self.backup = t


class Searchable(urwid.ListBox):
    def __init__(self, contents):
        self.walker = urwid.SimpleFocusListWalker(contents)
        urwid.ListBox.__init__(self, self.walker)
        self.search_offset = 0
        self.current_highlight = None
        self.search_term = None
        self.last_search = None

    def keypress(self, size, key: str):
        if key == "/":
            signals.status_prompt.send(
                prompt="Search for", text="", callback=self.set_search
            )
        elif key == "n":
            self.find_next(False)
        elif key == "N":
            self.find_next(True)
        elif key == "m_start":
            self._jump_to(size, 0, to_start=True)
            self.walker._modified()
        elif key == "m_end":
            self._jump_to(size, len(self.walker) - 1, to_start=False)
            self.walker._modified()
        else:
            return super().keypress(size, key)

    def _jump_to(self, size, position, to_start):
        """Move focus to ``position`` and scroll it fully into view.

        Unlike a plain ``set_focus``, this also handles the case where the
        target is a single widget taller than the viewport (e.g. a whole
        response body rendered as one urwid.Text). In that case we scroll
        *within* the widget so that "go to start"/"go to end" reveal its top
        or bottom rather than anchoring its top to the viewport.
        """
        maxcol, maxrow = size
        # Set the focus directly on the walker and clear any pending focus so
        # urwid doesn't re-align the widget's top on the next render (which
        # happens when the target is partially visible and would prevent us
        # from scrolling to the bottom of a tall widget).
        self.body.set_focus(position)
        self.set_focus_pending = None
        focus_widget, _ = self.body.get_focus()
        rows = focus_widget.rows((maxcol,), True)
        # offset 0 -> top of focus at viewport top (go to start);
        # offset maxrow - rows -> bottom of focus at viewport bottom (go to end).
        self.shift_focus(size, 0 if to_start else maxrow - rows)

    def set_search(self, text):
        self.last_search = text
        self.search_term = text or None
        self.find_next(False)

    def set_highlight(self, offset):
        if self.current_highlight is not None:
            old = self.body[self.current_highlight]
            self.body[self.current_highlight] = old.backup
        if offset is None:
            self.current_highlight = None
        else:
            self.body[offset] = Highlight(self.body[offset])
            self.current_highlight = offset

    def get_text(self, w):
        if isinstance(w, urwid.Text):
            return w.text
        elif isinstance(w, Highlight):
            return w.backup.text
        else:
            return None

    def find_next(self, backwards: bool):
        if not self.search_term:
            if self.last_search:
                self.search_term = self.last_search
            else:
                self.set_highlight(None)
                return
        # Start search at focus + 1
        if backwards:
            rng = range(len(self.body) - 1, -1, -1)
        else:
            rng = range(1, len(self.body) + 1)
        for i in rng:
            off = (self.focus_position + i) % len(self.body)
            w = self.body[off]
            txt = self.get_text(w)
            if txt and self.search_term in txt:
                self.set_highlight(off)
                self.set_focus(off, coming_from="above")
                self.body._modified()
                return
        else:
            self.set_highlight(None)
            signals.status_message.send(message="Search not found.", expire=1)
