"""The identifier formatter, and that it matches its TypeScript twin.

The console and the PDF must cut an address the same way; a report whose ids
do not match the screen is a report nobody can cross-check.
"""

from __future__ import annotations

import re
from pathlib import Path

from api.format_id import ELLIPSIS, ID_HEAD, ID_TAIL, format_id, max_id_length

TXID = "a" * 64
ADDRESS = "bc1q1975bbb1616d4c004ac7159d1b64104d3705125f06cb48ef582c824304"


def test_a_long_identifier_is_cut_in_the_middle():
    assert format_id(TXID) == f"{'a' * ID_HEAD}{ELLIPSIS}{'a' * ID_TAIL}"
    assert len(format_id(TXID)) == max_id_length()


def test_nothing_is_ever_longer_than_the_maximum():
    for value in (TXID, ADDRESS, "x" * 1000, ""):
        assert len(format_id(value)) <= max_id_length()


def test_short_values_are_left_alone():
    """Shortening a ten-character label to an eleven-character one is worse
    than leaving it, and half an IP address is not an identifier."""
    for value in ("", "abc", "1.2.3.4", "C000001"):
        assert format_id(value) == value


def test_the_head_and_tail_are_configurable():
    out = format_id(TXID, head=12, tail=6)
    assert out.startswith("a" * 12) and out.endswith("a" * 6)
    assert len(out) == max_id_length(12, 6)


def test_the_defaults_match_the_typescript_twin():
    source = Path(__file__).resolve().parents[1] / "web/src/lib/formatId.ts"
    text = source.read_text()
    head = int(re.search(r"export const ID_HEAD = (\d+)", text).group(1))
    tail = int(re.search(r"export const ID_TAIL = (\d+)", text).group(1))
    assert (head, tail) == (ID_HEAD, ID_TAIL), (
        "web/src/lib/formatId.ts and api/format_id.py have drifted apart"
    )
