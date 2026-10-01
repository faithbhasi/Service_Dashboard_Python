"""Distinguished-name helpers shared by the providers and the allowlist checks (RFC 4514 aware)."""
from __future__ import annotations

import re

_ATTRIBUTE_TYPE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*|\d+(\.\d+)*)$")
_HEX = set("0123456789abcdefABCDEF")


def first_unescaped_comma(dn: str) -> int:
    i = 0
    while i < len(dn):
        if dn[i] == "\\":
            i += 2
            continue
        if dn[i] == ",":
            return i
        i += 1
    return -1


def split_rdns(dn: str) -> list[str]:
    """Splits a DN into its RDNs, honouring backslash escapes."""
    parts: list[str] = []
    start = 0
    i = 0
    while i < len(dn):
        if dn[i] == "\\":
            i += 2
            continue
        if dn[i] == ",":
            parts.append(dn[start:i].strip())
            start = i + 1
        i += 1
    parts.append(dn[start:].strip())
    return parts


def normalize(dn: str) -> str:
    out = []
    for r in split_rdns(dn):
        eq = r.find("=")
        out.append(r if eq < 0 else r[:eq].strip() + "=" + r[eq + 1:].strip())
    return ",".join(out)


def dn_equal(a: str, b: str) -> bool:
    """Case-insensitive, whitespace-insensitive comparison of two DNs."""
    return normalize(a).lower() == normalize(b).lower()


def is_under_or_equal(dn: str, ancestor: str) -> bool:
    """True if dn is the same as, or below, ancestor."""
    a = split_rdns(normalize(dn))
    b = split_rdns(normalize(ancestor))
    if not b or len(b) > len(a):
        return False
    return all(a[-i].lower() == b[-i].lower() for i in range(1, len(b) + 1))


def parent_dn(dn: str) -> str:
    """The OU (or container) that holds an object: everything after the first RDN of its DN."""
    i = first_unescaped_comma(dn)
    return "" if i < 0 else dn[i + 1:]


def _split_unescaped(s: str, sep: str) -> list[str]:
    parts, start, i = [], 0, 0
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == sep:
            parts.append(s[start:i])
            start = i + 1
        i += 1
    parts.append(s[start:])
    return parts


def _valid_value(v: str) -> bool:
    if not v:
        return True  # empty values are legal in RFC 4514
    i = 0
    while i < len(v):
        c = v[i]
        if c in "\0\n\r" or c in '"<>;':
            return False
        if c == "\\":
            if i + 1 >= len(v):
                return False
            n = v[i + 1]
            if n in _HEX and i + 2 < len(v) and v[i + 2] in _HEX:
                i += 3
                continue
            if n in ',+"\\<>;= #':
                i += 2
                continue
            return False
        i += 1
    return True


def is_valid_dn(dn: str | None) -> bool:
    """RFC 4514 shape check: comma-separated RDNs, each 'type=value' (multi-valued RDNs joined with an unescaped '+'),
    with backslash escapes as either a special character or two hex digits, and no unescaped specials."""
    if dn is None or not dn.strip() or len(dn) > 2048:
        return False
    for rdn in split_rdns(dn):
        if not rdn:
            return False
        for pair in _split_unescaped(rdn, "+"):
            eq = pair.find("=")
            if eq <= 0 or not _ATTRIBUTE_TYPE.match(pair[:eq].strip()):
                return False
            if not _valid_value(pair[eq + 1:]):
                return False
    return True


def ou_label(dn: str) -> str:
    """'OU=Sales,OU=Staff,OU=Corp,DC=x' -> 'Corp / Staff / Sales'."""
    parts = [r[3:] for r in split_rdns(dn) if r.upper().startswith(("OU=", "CN="))]
    return " / ".join(reversed(parts)) or dn
