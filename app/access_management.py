"""Manages roles, role assignments and Okta group mappings, and enforces the safeguards.

Nobody can raise their own access, nobody can manage a role more powerful than their own, the last Admins assignment cannot be removed,
and every change is audited (denied attempts too).
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import permissions as P
from .access import (
    COMPUTER_CHANGE_PERMISSIONS, GROUP_CHANGE_PERMISSIONS, USER_CHANGE_PERMISSIONS, AccessService, AppUser,
)
from .audit import AuditEntry, AuditService
from .current_user import CurrentUserInfo
from .db import GroupMapping, Role, UserRole
from .errors import ApiException
from .models import AdScope, AdScopeOptions, AdScopeOuNode
from .modules.ad.dn import dn_equal, is_under_or_equal
from .seed import set_permissions
from .db import AuditResult

MODULE = "core"


class AdScopeCatalog(Protocol):
    """Implemented by the Active Directory module so the core can check a role's scope against the global allowlists."""

    def get_options(self) -> AdScopeOptions: ...
    def browse_ous(self, kind: str, parent_dn: str | None, search: str | None) -> list[AdScopeOuNode]: ...
    def is_selectable(self, kind: str, dn: str) -> bool: ...


def role_dto(r: Role, users: int, maps: int) -> dict:
    return {
        "id": r.id, "name": r.name, "description": r.description, "isSystem": r.is_system, "isLocked": r.id == str(P.ADMINS_ID),
        "permissions": sorted(p.permission for p in r.permissions), "userCount": users, "mappingCount": maps,
        "adScope": AdScope.parse(r.ad_scope_json).to_dict(),
    }


def _describe_scope(s: AdScope) -> str:
    def one(label: str, lst: list[str] | None) -> str:
        return f"{label}={'all allowed' if lst is None else 'none' if not lst else ' ; '.join(lst)}"

    return " | ".join([one("user OUs", s.user_ous), one("computer OUs", s.computer_ous), one("groups", s.groups)])


def _describe(name: str, perms: Iterable[str], scope: AdScope | None = None) -> str:
    text = f"{name}: {', '.join(sorted(perms))}"
    if scope is not None and not scope.is_unrestricted:
        text += " | AD scope: " + _describe_scope(scope)
    return text


def _within(dn: str, reference: list[str], kind: str) -> bool:
    """OUs are 'within' when they are the same as, or below, one of the OUs in the list (a scope OU covers its sub-OUs); groups must match exactly."""
    return any(dn_equal(r, dn) if kind == "groups" else is_under_or_equal(dn, r) for r in reference)


def _not_found(what: str) -> ApiException:
    return ApiException(404, "Not found", f"{what} not found.", "not_found")


class AccessManagementService:
    def __init__(self, db: Session, caller: CurrentUserInfo, audit: AuditService, access: AccessService, catalog: AdScopeCatalog | None = None):
        self.db = db
        self.caller = caller
        self.audit = audit
        self.access = access
        self.catalog = catalog

    # ---------- roles ----------

    def list_roles(self) -> list[dict]:
        roles = list(self.db.scalars(select(Role).order_by(Role.name)))
        users = dict(self.db.execute(select(UserRole.role_id, func.count()).group_by(UserRole.role_id)).all())
        maps = dict(self.db.execute(select(GroupMapping.role_id, func.count()).group_by(GroupMapping.role_id)).all())
        return [role_dto(r, users.get(r.id, 0), maps.get(r.id, 0)) for r in roles]

    def create_role(self, name: str, description: str | None, permissions: Iterable[str], scope: AdScope | None = None,
                    audit_action: str = "admin.role.create") -> dict:
        perms = self._validate_permissions(permissions)
        name = self._validate_name(name, None)
        self._require_can_grant(perms, audit_action, name)
        new_scope = self._validate_scope(scope or AdScope(), None, perms, audit_action, name)

        role = Role(name=name, description=description.strip() if description is not None else None, ad_scope_json=new_scope.to_json())
        self.db.add(role)
        set_permissions(role, perms)
        self.db.commit()
        self.audit.write(AuditEntry(action=audit_action, module=MODULE, target="Role: " + name, target_id=role.id,
                                    new_value=_describe(role.name, perms, new_scope)))
        return role_dto(role, 0, 0)

    def clone_role(self, role_id: str, name: str) -> dict:
        source = self.db.get(Role, role_id)
        if source is None:
            raise _not_found("Role")
        return self.create_role(name, source.description, [p.permission for p in source.permissions], AdScope.parse(source.ad_scope_json), "admin.role.clone")

    def update_role(self, role_id: str, name: str, description: str | None, permissions: Iterable[str], scope: AdScope | None = None) -> dict:
        role = self.db.get(Role, role_id)
        if role is None:
            raise _not_found("Role")
        perms = self._validate_permissions(permissions)
        old_scope = AdScope.parse(role.ad_scope_json)
        before = _describe(role.name, [p.permission for p in role.permissions], old_scope)

        if role.id == str(P.ADMINS_ID):
            raise self._deny("admin.role.update", role, "The Admins role always has every permission and cannot be edited.")
        if role.is_system and (name or "").strip() != role.name:
            raise self._deny("admin.role.update", role, "Default roles cannot be renamed.")

        name = self._validate_name(name, role.id)
        added = [p for p in perms if p not in {x.permission for x in role.permissions}]
        self._require_can_grant(added, "admin.role.update", role.name, role)
        new_scope = old_scope if scope is None else self._validate_scope(scope, old_scope, perms, "admin.role.update", role.name, role)

        role.name = name
        role.description = description.strip() if description is not None else None
        role.ad_scope_json = new_scope.to_json()
        set_permissions(role, perms)
        self.db.commit()
        self.audit.write(AuditEntry(action="admin.role.update", module=MODULE, target="Role: " + name, target_id=role.id,
                                    previous_value=before, new_value=_describe(name, perms, new_scope)))
        users = self.db.scalar(select(func.count()).select_from(UserRole).where(UserRole.role_id == role_id)) or 0
        maps = self.db.scalar(select(func.count()).select_from(GroupMapping).where(GroupMapping.role_id == role_id)) or 0
        return role_dto(role, users, maps)

    def delete_role(self, role_id: str) -> None:
        role = self.db.get(Role, role_id)
        if role is None:
            raise _not_found("Role")
        if role.is_system:
            raise self._deny("admin.role.delete", role, "The default roles cannot be deleted.")
        if self.db.scalar(select(UserRole).where(UserRole.role_id == role_id).limit(1)) or self.db.scalar(select(GroupMapping).where(GroupMapping.role_id == role_id).limit(1)):
            raise self._deny("admin.role.delete", role, "This role is still assigned to users or mapped to Okta groups. Remove those first.", 409)
        previous = _describe(role.name, [p.permission for p in role.permissions], AdScope.parse(role.ad_scope_json))
        name = role.name
        self.db.delete(role)
        self.db.commit()
        self.audit.write(AuditEntry(action="admin.role.delete", module=MODULE, target="Role: " + name, target_id=role_id, previous_value=previous))

    # ---------- app users ----------

    def set_user_status(self, user_id: str, enabled: bool) -> None:
        user = self.db.get(AppUser, user_id)
        if user is None:
            raise _not_found("User")
        action = "admin.user.enable" if enabled else "admin.user.disable"
        if user.id == self.caller.id:
            raise self._deny(action, user, "You cannot change your own access to this application.")
        if user.is_enabled == enabled:
            return
        target = self.access.resolve(user)
        self._require_holds(target.permissions, action, user)
        if not enabled and any(r.role_id == str(P.ADMINS_ID) for r in user.user_roles) and self._admin_assignments(exclude_user=user.id) == 0:
            raise self._deny(action, user, "This is the last Admins assignment and cannot be removed.", 409)
        was = user.is_enabled
        user.is_enabled = enabled
        self.db.commit()
        self.audit.write(AuditEntry(action=action, module=MODULE, target="App user: " + user.display_name, target_id=user.id,
                                    previous_value="Enabled" if was else "Disabled", new_value="Enabled" if enabled else "Disabled"))

    def set_user_roles(self, user_id: str, role_ids: Iterable[str]) -> None:
        user = self.db.get(AppUser, user_id)
        if user is None:
            raise _not_found("User")
        if user.id == self.caller.id:
            raise self._deny("admin.user.roles", user, "You cannot change your own roles.")
        roles = {r.id: r for r in self.db.scalars(select(Role))}
        wanted = list(dict.fromkeys(role_ids))
        if any(r not in roles for r in wanted):
            raise ApiException(400, "Unknown role", "One of the selected roles does not exist.", "validation")

        current = {r.role_id for r in user.user_roles}
        changed = [r for r in wanted if r not in current] + [r for r in current if r not in wanted]
        for rid in changed:
            self._require_holds({p.permission for p in roles[rid].permissions}, "admin.user.roles", user)
        for rid in [r for r in wanted if r not in current]:
            self._require_scope_within(roles[rid], "admin.user.roles", user)

        if str(P.ADMINS_ID) in current and str(P.ADMINS_ID) not in wanted and user.is_enabled and self._admin_assignments(exclude_user=user.id) == 0:
            raise self._deny("admin.user.roles", user, "This is the last Admins assignment and cannot be removed.", 409)

        before = ", ".join(sorted(roles[r].name for r in current))
        for ur in [x for x in user.user_roles if x.role_id not in wanted]:
            user.user_roles.remove(ur)
        for rid in wanted:
            if rid not in current:
                user.user_roles.append(UserRole(user_id=user.id, role_id=rid))
        self.db.commit()
        self.audit.write(AuditEntry(action="admin.user.roles", module=MODULE, target="App user: " + user.display_name, target_id=user.id,
                                    previous_value=before, new_value=", ".join(sorted(roles[r].name for r in wanted))))

    # ---------- Okta group mappings ----------

    def add_mapping(self, okta_group: str, role_id: str) -> GroupMapping:
        okta_group = (okta_group or "").strip()
        if len(okta_group) == 0 or len(okta_group) > 256:
            raise ApiException(400, "Invalid group", "Enter the Okta group name (up to 256 characters).", "validation")
        role = self.db.get(Role, role_id)
        if role is None:
            raise _not_found("Role")
        self._require_holds({p.permission for p in role.permissions}, "admin.mapping.create", role)
        self._require_scope_within(role, "admin.mapping.create", role)
        if self.db.scalar(select(GroupMapping).where(GroupMapping.okta_group == okta_group, GroupMapping.role_id == role_id)) is not None:
            raise ApiException(409, "Already mapped", "That Okta group is already mapped to this role.", "conflict")
        m = GroupMapping(okta_group=okta_group, role_id=role_id)
        self.db.add(m)
        self.db.commit()
        self.audit.write(AuditEntry(action="admin.mapping.create", module=MODULE, target="Okta group: " + okta_group, target_id=m.id,
                                    new_value=f"{okta_group} -> {role.name}"))
        return m

    def delete_mapping(self, mapping_id: str) -> None:
        m = self.db.get(GroupMapping, mapping_id)
        if m is None:
            raise _not_found("Mapping")
        self._require_holds({p.permission for p in m.role.permissions}, "admin.mapping.delete", m.role)
        if m.role_id == str(P.ADMINS_ID) and self._admin_assignments(exclude_mapping=mapping_id) == 0:
            raise self._deny("admin.mapping.delete", m.role, "This is the last Admins assignment and cannot be removed.", 409)
        group, role_name = m.okta_group, m.role.name
        self.db.delete(m)
        self.db.commit()
        self.audit.write(AuditEntry(action="admin.mapping.delete", module=MODULE, target="Okta group: " + group, target_id=mapping_id,
                                    previous_value=f"{group} -> {role_name}"))

    # ---------- helpers ----------

    def _admin_assignments(self, exclude_user: str | None = None, exclude_mapping: str | None = None) -> int:
        """Admins assignments that would remain: enabled users holding the role directly plus Okta group mappings to it."""
        q = select(func.count()).select_from(UserRole).join(AppUser, AppUser.id == UserRole.user_id).where(
            UserRole.role_id == str(P.ADMINS_ID), AppUser.is_enabled.is_(True))
        if exclude_user:
            q = q.where(UserRole.user_id != exclude_user)
        direct = self.db.scalar(q) or 0
        mq = select(func.count()).select_from(GroupMapping).where(GroupMapping.role_id == str(P.ADMINS_ID))
        if exclude_mapping:
            mq = mq.where(GroupMapping.id != exclude_mapping)
        return direct + (self.db.scalar(mq) or 0)

    @staticmethod
    def _validate_permissions(permissions: Iterable[str]) -> list[str]:
        lst = list(dict.fromkeys(permissions))
        unknown = [p for p in lst if p not in P.ALL_IDS]
        if unknown:
            raise ApiException(400, "Unknown permission", "Unknown permission: " + ", ".join(unknown), "validation")
        return lst

    def _validate_name(self, name: str | None, own_id: str | None) -> str:
        name = (name or "").strip()
        if len(name) == 0 or len(name) > 100:
            raise ApiException(400, "Invalid name", "Enter a role name (up to 100 characters).", "validation")
        existing = self.db.scalar(select(Role).where(Role.name == name))
        if existing is not None and existing.id != own_id:
            raise ApiException(409, "Name in use", "A role with that name already exists.", "conflict")
        return name

    def _require_can_grant(self, perms: Iterable[str], action: str, target_name: str, role: Role | None = None) -> None:
        missing = [p for p in perms if p not in self.caller.permissions]
        if not missing:
            return
        self.audit.write(AuditEntry(action=action, module=MODULE, target="Role: " + target_name, target_id=role.id if role else None,
                                    result=AuditResult.DENIED, error="Cannot grant permissions you do not hold: " + ", ".join(missing)))
        raise ApiException(403, "Not allowed", "You cannot grant permissions you do not hold yourself: " + ", ".join(missing), "escalation")

    def _require_holds(self, needed: set[str], action: str, target) -> None:
        missing = [p for p in needed if p not in self.caller.permissions]
        if not missing:
            return
        raise self._deny(action, target, "You can only manage access that is no more powerful than your own. You lack: " + ", ".join(missing), 403)

    def _deny(self, action: str, target, message: str, status: int = 403) -> ApiException:
        if isinstance(target, Role):
            name, tid = "Role: " + target.name, target.id
        elif isinstance(target, AppUser):
            name, tid = "App user: " + target.display_name, target.id
        else:
            name, tid = str(target), None
        self.audit.write(AuditEntry(action=action, module=MODULE, target=name, target_id=tid, result=AuditResult.DENIED, error=message))
        return ApiException(status, "Conflict" if status == 409 else "Not allowed", message, "safeguard" if status == 409 else "forbidden")

    # ---------- AD scope (which OUs and groups a role may manage) ----------

    def _validate_scope(self, requested: AdScope, existing: AdScope | None, role_permissions: Iterable[str], action: str, role_name: str,
                        role: Role | None = None) -> AdScope:
        """Checks a role's scope: every new entry must be inside the global manageable lists, and nobody may widen a scope beyond their own reach.

        For a kind of object they cannot change themselves, a person can keep or narrow what a role may manage, never widen it.
        """
        def clean(lst: list[str] | None) -> list[str] | None:
            if lst is None:
                return None
            out: dict[str, str] = {}
            for x in lst:
                x = (x or "").strip()
                if x:
                    out.setdefault(x.lower(), x)
            return list(out.values())

        nxt = AdScope(clean(requested.user_ous), clean(requested.computer_ous), clean(requested.groups))
        if nxt.is_unrestricted and existing is not None and existing.is_unrestricted:
            return nxt
        existing = existing or AdScope()
        role_perms = set(role_permissions)

        def check(label: str, kind: str, relevant: list[str], want: list[str] | None, had: list[str] | None, mine: list[str] | None) -> None:
            if want is None and had is None and not role_perms.intersection(relevant):
                return  # nothing to limit for a role that cannot change these
            # Only entries that are new have to be selectable now; one that was already there stays even if Settings has moved on since.
            unknown = [d for d in (want or []) if not any(dn_equal(h, d) for h in (had or []))
                       and (self.catalog is None or not self.catalog.is_selectable(kind, d))]
            if unknown:
                raise ApiException(400, "Not on the allowed list",
                                   f"These {label} are not on the manageable list in Settings > AD Integration: {'; '.join(unknown)}", "validation")
            caller_can = any(p in self.caller.permissions for p in relevant)
            # Anything the person could not manage themselves (or a role broader than they may grant) is refused.
            reference = mine if caller_can else had
            widens = reference is not None and (want is None or any(not _within(d, reference, kind) for d in want))
            if want is None and not role_perms.intersection(relevant):
                widens = False  # "no limit" only matters to a role that can change these objects
            if not widens:
                return
            why = (f"You can only give a role the {label} that you can manage yourself." if caller_can
                   else f"You can narrow what a role may manage, but not widen it: you cannot change {label} yourself.")
            self.audit.write(AuditEntry(action=action, module=MODULE, target="Role: " + role_name, target_id=role.id if role else None,
                                        result=AuditResult.DENIED, error=why))
            raise ApiException(403, "Not allowed", why, "escalation")

        mine_scope = self.caller.ad_scope
        check("user OUs", "users", USER_CHANGE_PERMISSIONS, nxt.user_ous, existing.user_ous, mine_scope.user_ous)
        check("computer OUs", "computers", COMPUTER_CHANGE_PERMISSIONS, nxt.computer_ous, existing.computer_ous, mine_scope.computer_ous)
        check("groups", "groups", GROUP_CHANGE_PERMISSIONS, nxt.groups, existing.groups, mine_scope.groups)
        return nxt

    def _require_scope_within(self, role: Role, action: str, target) -> None:
        """A role broader than the assigner's own reach cannot be handed out (for example by assigning it to someone)."""
        scope = AdScope.parse(role.ad_scope_json)
        mine = self.caller.ad_scope
        if role.id == str(P.ADMINS_ID):
            return  # already guarded by the permission check

        def wider(want: list[str] | None, have: list[str] | None, kind: str) -> bool:
            return have is not None and (want is None or any(not _within(d, have, kind) for d in want))

        if wider(scope.user_ous, mine.user_ous, "users") or wider(scope.computer_ous, mine.computer_ous, "computers") or wider(scope.groups, mine.groups, "groups"):
            raise self._deny(action, target, "This role can manage more of Active Directory than you can, so you cannot assign it.", 403)
