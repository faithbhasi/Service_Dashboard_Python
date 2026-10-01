"""CSV output with formula-injection protection: cells starting with = + - @ (or tab/CR) get a leading apostrophe."""
from __future__ import annotations

from collections.abc import Iterable, Iterator


def cell(value: str | None) -> str:
    if not value:
        return ""
    v = value
    if v[0] in "=+-@\t\r":
        v = "'" + v
    if any(c in v for c in ',"\r\n'):
        v = '"' + v.replace('"', '""') + '"'
    return v


def row(cells: Iterable[str | None]) -> str:
    return ",".join(cell(c) for c in cells)


def stream(header: Iterable[str], rows: Iterable[Iterable[str | None]]) -> Iterator[bytes]:
    """Yields the file piece by piece (UTF-8 with a byte order mark, as Excel expects). Nothing is buffered beyond one row."""
    yield b"\xef\xbb\xbf" + (row(header) + "\r\n").encode("utf-8")
    for r in rows:
        yield (row(r) + "\r\n").encode("utf-8")
