"""Escaping and validation for text that ends up in LDAP filters and distinguished names, and the LDAP filter builders.

Every piece of user input is escaped with escape_filter_value."""
from __future__ import annotations

import re
import uuid
from datetime import datetime

from . import user_status as us
from .provider import ComputerFilter, MemberKind, UserFilter, os_type_match

_FILTER_ESCAPES = {"\\": "\\5c", "*": "\\2a", "(": "\\28", ")": "\\29", "\0": "\\00"}
_ATTRIBUTE_NAME = re.compile(r"\A[A-Za-z][A-Za-z0-9-]{0,63}\Z")


def escape_filter_value(value: str | None) -> str:
    """RFC 4515 filter value escaping: \\ * ( ) and NUL. Every user-supplied search term goes through this."""
    return "" if not value else "".join(_FILTER_ESCAPES.get(ch, ch) for ch in value)


def append_rid(domain_sid: bytes, rid: int) -> bytes:
    """The binary SID of a domain object: the domain SID with one more sub-authority (the RID) appended."""
    if len(domain_sid) < 8 or domain_sid[1] >= 15:
        raise ValueError("Not a domain SID.")
    out = bytearray(domain_sid)
    out[1] += 1  # one more sub-authority
    out += int(rid).to_bytes(4, "little", signed=True)
    return bytes(out)


def escape_bytes(data: bytes) -> str:
    return "".join("\\" + format(b, "02x") for b in data)


def escape_guid(id_: uuid.UUID) -> str:
    """Binary GUID as an LDAP filter value: \\xx per byte (the .NET / Active Directory byte order)."""
    return escape_bytes(id_.bytes_le)


def escape_dn_value(value: str) -> str:
    """RFC 4514 DN attribute value escaping."""
    out = []
    for i, c in enumerate(value):
        if c in ',+"\\<>;=' or (i == 0 and c in "# ") or (i == len(value) - 1 and c == " "):
            out.append("\\")
        if c == "\0":
            out.append("\\00")
            continue
        out.append(c)
    return "".join(out)


def is_safe_attribute_name(name: str | None) -> bool:
    """Only plain attribute names may be used from settings, so a setting can never inject filter syntax."""
    return name is not None and _ATTRIBUTE_NAME.match(name) is not None


USER_BASE = "(&(objectCategory=person)(objectClass=user))"
COMPUTER_BASE = "(objectCategory=computer)"
GROUP_BASE = "(objectCategory=group)"
IN_CHAIN = "1.2.840.113556.1.4.1941"
BIT_AND = "1.2.840.113556.1.4.803"


def users_filter(text: str | None, flt: UserFilter, employee_id_attribute: str, now_utc: datetime,
                 department: str | None = None, title: str | None = None) -> str:
    parts = [USER_BASE]
    t = escape_filter_value(text.strip() if text else None)
    if t:
        emp = employee_id_attribute if is_safe_attribute_name(employee_id_attribute) else "employeeID"
        parts.append(f"(|(sAMAccountName=*{t}*)(userPrincipalName=*{t}*)(displayName=*{t}*)(givenName=*{t}*)(sn=*{t}*)(mail=*{t}*)({emp}=*{t}*))")
    dept = escape_filter_value(department.strip() if department else None)
    if dept:
        parts.append(f"(department=*{dept}*)")
    ttl = escape_filter_value(title.strip() if title else None)
    if ttl:
        parts.append(f"(title=*{ttl}*)")
    if flt == UserFilter.Disabled:
        parts.append(f"(userAccountControl:{BIT_AND}:=2)")
    elif flt == UserFilter.Enabled:
        parts.append(f"(!(userAccountControl:{BIT_AND}:=2))")
    elif flt == UserFilter.Locked:
        parts.append("(lockoutTime>=1)")  # confirmed afterwards with msDS-User-Account-Control-Computed
    elif flt == UserFilter.AccountExpired:
        parts.append(f"(&(accountExpires>=1)(accountExpires<={us.to_filetime(now_utc)}))")
    return "(&" + "".join(parts) + ")"


def computers_filter(text: str | None, flt: ComputerFilter, os_type: str | None = None) -> str:
    parts = [COMPUTER_BASE]
    t = escape_filter_value(text.strip() if text else None)
    if t:
        parts.append(f"(|(cn=*{t}*)(dNSHostName=*{t}*))")
    os_matches = os_type_match(os_type)
    if os_matches:
        parts.append("(|" + "".join(f"(operatingSystem=*{escape_filter_value(o)}*)" for o in os_matches) + ")")
    if flt == ComputerFilter.Disabled:
        parts.append(f"(userAccountControl:{BIT_AND}:=2)")
    if flt == ComputerFilter.Enabled:
        parts.append(f"(!(userAccountControl:{BIT_AND}:=2))")
    return "(&" + "".join(parts) + ")"


def groups_filter(text: str | None) -> str:
    t = escape_filter_value(text.strip() if text else None)
    return GROUP_BASE if not t else f"(&{GROUP_BASE}(|(cn=*{t}*)(description=*{t}*)))"


def members_filter(group_dn: str, text: str | None, kind: MemberKind | None) -> str:
    """Direct members of a group that match the text and kind, evaluated by the directory server."""
    kind_filter = {MemberKind.User: USER_BASE, MemberKind.Computer: COMPUTER_BASE, MemberKind.Group: GROUP_BASE}.get(
        kind, f"(|{USER_BASE}{COMPUTER_BASE}{GROUP_BASE})")
    t = escape_filter_value(text.strip() if text else None)
    text_filter = "" if not t else f"(|(cn=*{t}*)(sAMAccountName=*{t}*)(mail=*{t}*)(displayName=*{t}*))"
    return f"(&(memberOf={escape_filter_value(group_dn)}){kind_filter}{text_filter})"


def by_guid(id_: uuid.UUID) -> str:
    return f"(objectGUID={escape_guid(id_)})"


def nested_groups_of(dn: str) -> str:
    return f"(&{GROUP_BASE}(member:{IN_CHAIN}:={escape_filter_value(dn)}))"

