"""Which roles (direct assignment or Okta group mapping) and permissions a user has, and what they may manage in AD."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import permissions as P
from .db import AppUser, GroupMapping, Role, UserRole
from .models import AdScope


@dataclass(frozen=True)
class RoleRef:
    id: str
    name: str
    source: str


@dataclass
class ResolvedAccess:
    roles: list[RoleRef]
    permissions: set[str]
    ad_scope: AdScope = field(default_factory=AdScope)


USER_CHANGE_PERMISSIONS = [
    P.AD_USERS_RESET_PASSWORD, P.AD_USERS_UNLOCK, P.AD_USERS_ENABLE, P.AD_USERS_DISABLE, P.AD_USERS_MOVE,
    P.AD_USERS_GROUPS_ADD, P.AD_USERS_GROUPS_REMOVE,
]
COMPUTER_CHANGE_PERMISSIONS = [P.AD_COMPUTERS_ENABLE, P.AD_COMPUTERS_DISABLE, P.AD_COMPUTERS_MOVE]
GROUP_CHANGE_PERMISSIONS = [P.AD_USERS_GROUPS_ADD, P.AD_USERS_GROUPS_REMOVE]


def parse_groups(raw: str) -> set[str]:
    try:
        return {str(g) for g in (json.loads(raw) or [])}
    except (ValueError, TypeError):
        return set()


def effective_scope(roles: list[Role]) -> AdScope:
    """What all of a person's roles together may manage.

    Only roles that can change that kind of object count (a read-only role must not widen a helpdesk role), the Admins role is never
    limited, and a role with no limit makes the result unlimited for that kind.
    """
    info = [(r, AdScope.parse(r.ad_scope_json), {p.permission for p in r.permissions}) for r in roles]

    def combine(relevant: list[str], pick) -> list[str] | None:
        counted = [x for x in info if x[2].intersection(relevant)]
        if not counted:
            return None  # nothing to limit: they cannot change this kind of object anyway
        if any(r.id == str(P.ADMINS_ID) or pick(s) is None for r, s, _ in counted):
            return None
        seen: dict[str, str] = {}
        for _, s, _ in counted:
            for dn in pick(s):
                seen.setdefault(dn.lower(), dn)
        return list(seen.values())

    return AdScope(
        user_ous=combine(USER_CHANGE_PERMISSIONS, lambda s: s.user_ous),
        computer_ous=combine(COMPUTER_CHANGE_PERMISSIONS, lambda s: s.computer_ous),
        groups=combine(GROUP_CHANGE_PERMISSIONS, lambda s: s.groups),
    )


class AccessService:
    def __init__(self, db: Session):
        self.db = db

    def resolve(self, user: AppUser) -> ResolvedAccess:
        return self.resolve_many([user])[user.id]

    def resolve_many(self, users: list[AppUser]) -> dict[str, ResolvedAccess]:
        roles = {r.id: r for r in self.db.scalars(select(Role))}
        mappings = list(self.db.scalars(select(GroupMapping)))
        ids = [u.id for u in users]
        direct = list(self.db.scalars(select(UserRole).where(UserRole.user_id.in_(ids)))) if ids else []

        result: dict[str, ResolvedAccess] = {}
        for u in users:
            refs: dict[str, RoleRef] = {}
            for ur in (d for d in direct if d.user_id == u.id):
                r = roles.get(ur.role_id)
                if r is not None:
                    refs[r.id] = RoleRef(r.id, r.name, "Assigned in this app")
            groups_lower = {g.lower() for g in parse_groups(u.okta_groups_json)}
            for m in mappings:
                if m.okta_group.lower() in groups_lower:
                    r = roles.get(m.role_id)
                    if r is not None and r.id not in refs:
                        refs[r.id] = RoleRef(r.id, r.name, f"Okta group: {m.okta_group}")
            perms = {p.permission for rr in refs.values() for p in roles[rr.id].permissions if p.permission in P.ALL_IDS}
            result[u.id] = ResolvedAccess(sorted(refs.values(), key=lambda r: r.name), perms, effective_scope([roles[r] for r in refs]))
        return result
