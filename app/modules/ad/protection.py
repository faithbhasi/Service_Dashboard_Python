"""Allowlists and protected objects. The backend applies these to fresh data on every change,
so sending a request straight to the API cannot get around them."""
from __future__ import annotations

import re
from collections.abc import Iterable

from ...models import AdScope
from .dn import dn_equal, is_under_or_equal, split_rdns
from .provider import DirectoryGroup, ObjectKind
from .settings import AdSettings

# Groups that can never be changed in Version 1.
BUILT_IN_PROTECTED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators",
    "Backup Operators", "Server Operators", "Print Operators",
]
_BUILT_IN_UPPER = {g.upper() for g in BUILT_IN_PROTECTED_GROUPS}

# OU names that always mean "admin" or "service" tiers. Deliberately broad: blocking too much is the safe failure.
_SENSITIVE_OU = re.compile(r"tier[\s_-]*0|admin|service[\s_-]*account|^svc\b|privileged", re.IGNORECASE)


def _is_ou(rdn: str) -> bool:
    return rdn.upper().startswith("OU=")


# ---------- groups ----------

def is_group_protected(g: DirectoryGroup, s: AdSettings) -> bool:
    return (g.admin_count or g.name.upper() in _BUILT_IN_UPPER
            or any(p.upper() == g.name.upper() or dn_equal(p, g.dn) for p in s.protected_groups))


def is_group_on_allowlist(g: DirectoryGroup, s: AdSettings) -> bool:
    return any(dn_equal(a, g.dn) for a in s.manageable_groups)


def group_block_reason(g: DirectoryGroup, s: AdSettings) -> str | None:
    """None when the group may be added to or removed from; otherwise the reason it may not."""
    if is_group_protected(g, s):
        return f"'{g.name}' is a protected group and cannot be changed in this application."
    if not is_group_on_allowlist(g, s):
        return f"'{g.name}' is not on the manageable groups allowlist."
    return None


# ---------- OUs ----------

def ou_block_reason(ou_dn: str, s: AdSettings, base_dn: str) -> str | None:
    """Why an OU (or the OU an object sits in) is always off limits, or None."""
    if not ou_dn or not ou_dn.strip():
        return "The OU is unknown."
    rdns = split_rdns(ou_dn)
    if any(_is_ou(r) and r[3:].strip().upper() == "DOMAIN CONTROLLERS" for r in rdns):
        return "Domain Controllers cannot be changed or moved."
    if not _is_ou(rdns[0]) and not any(_is_ou(r) for r in rdns):
        return "Objects in built-in containers (CN=...) cannot be changed or moved."
    if any(_is_ou(r) and _SENSITIVE_OU.search(r[3:]) for r in rdns):
        return "Admin, Tier 0 and service account OUs are always blocked."
    if any(is_under_or_equal(ou_dn, p) for p in s.protected_ous):
        return "This OU is on the protected OUs list."
    return None


def ou_use_reason(ou_dn: str, allowlist: Iterable[str], s: AdSettings, base_dn: str) -> str | None:
    """None when objects in this OU may be changed or moved into it; otherwise the reason."""
    blocked = ou_block_reason(ou_dn, s, base_dn)
    if blocked:
        return blocked
    return None if any(is_under_or_equal(ou_dn, a) for a in allowlist) else "This OU is not on the manageable OU allowlist."


def allowlist_for(kind: ObjectKind, s: AdSettings) -> list[str]:
    return s.manageable_computer_ous if kind == ObjectKind.Computer else s.manageable_user_ous


# ---------- role scope ----------
# The extra limit a role puts on what its holders may manage, on top of the global allowlists and protected objects
# (which always still apply). A None list in the scope means the role adds no limit.

def scope_ou_reason(scope: AdScope, kind: ObjectKind, ou_dn: str) -> str | None:
    allowed = scope.computer_ous if kind == ObjectKind.Computer else scope.user_ous
    if allowed is None:
        return None
    return None if any(is_under_or_equal(ou_dn, a) for a in allowed) else "Your role is not allowed to manage objects in this OU."


def scope_group_reason(scope: AdScope, group_dn: str) -> str | None:
    if scope.groups is None or any(dn_equal(g, group_dn) for g in scope.groups):
        return None
    return "Your role is not allowed to manage this group."
