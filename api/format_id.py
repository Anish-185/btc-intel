"""One way to shorten an identifier, on the Python side.

The twin of `web/src/lib/formatId.ts`: same defaults, same rule, so an address
in the PDF case report is cut the same way it was cut on the screen the
investigator was reading. A report whose ids do not match the console's is a
report nobody can cross-check.

If you change the defaults here, change them there.
"""

from __future__ import annotations

# Leading characters kept — the script prefix plus four.
ID_HEAD = 6
# Trailing characters kept — what an investigator reads back from a note.
ID_TAIL = 4
ELLIPSIS = "…"


def max_id_length(head: int = ID_HEAD, tail: int = ID_TAIL) -> int:
    """The longest string format_id can return for a given setting."""
    return head + len(ELLIPSIS) + tail


def format_id(value: str, head: int = ID_HEAD, tail: int = ID_TAIL) -> str:
    """Middle-truncate an identifier: ``bc1qdf…d061``.

    Values already short enough come back untouched: shortening a ten-character
    label to an eleven-character one would be worse than leaving it, and half
    an IP address is not an identifier at all.
    """
    text = "" if value is None else str(value)
    if len(text) <= max_id_length(head, tail):
        return text
    return f"{text[:head]}{ELLIPSIS}{text[-tail:]}"
