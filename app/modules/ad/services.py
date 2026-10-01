"""The Active Directory module's services: the read side (annotated with protection state), the one change pipeline,
the role-scope catalog, and the search and dashboard hooks."""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import quote

import regex

from ...audit import AuditEntry
from ...current_user import CurrentUserInfo
from ...db import AuditResult
from ...errors import ApiException, ModuleUnavailableError
from ...models import AdScope, AdScopeOption, AdScopeOptions, AdScopeOuNode
from ... import permissions as P
from ...request_context import correlation_id
from ...settings_models import ActionKeys, ActionPolicy
from ...util import utcnow
from . import protection as prot
from .dn import dn_equal, is_under_or_equal, is_valid_dn, ou_label
from .provider import (
    ComputerFilter, ComputerSearch, DirectoryChange, DirectoryComputer, DirectoryErrors, DirectoryGroup, DirectoryProvider,
    DirectoryResult, DirectoryUser, DryRunCheck, GroupMember, GroupSearch, MemberKind, MemberSearch, ObjectKind, ObjectRef, PagedResult,
    ResetPasswordOptions, UserFilter, UserSearch, os_type_match,
)
from .settings import AdSettings, AdSettingsService

if TYPE_CHECKING:
    from ...web import Ctx

MODULE_ID = "ad"


# ====================================================================================== DTOs

@dataclass
class GroupDto:
    id: uuid.UUID
    dn: str
    ou: str
    name: str
    description: str | None
    scope: str
    type: str
    managed_by: ObjectRef | None
    member_count: int | None
    is_protected: bool
    is_manageable: bool
    block_reason: str | None

    @staticmethod
    def from_group(g: DirectoryGroup, s: AdSettings, role: AdScope | None = None) -> GroupDto:
        reason = prot.group_block_reason(g, s) or (None if role is None else prot.scope_group_reason(role, g.dn))
        return GroupDto(g.id, g.dn, g.ou, g.name, g.description, g.scope, g.type, g.managed_by, g.member_count,
                        prot.is_group_protected(g, s), reason is None, reason)


@dataclass
class NestedGroupDto:
    group: GroupDto
    via: str | None


@dataclass
class MembershipsDto:
    direct: list[GroupDto]
    nested: list[NestedGroupDto]
    primary: GroupDto | None


@dataclass
class UserDetail:
    user: DirectoryUser
    ou_manageable: bool
    ou_reason: str | None


@dataclass
class ComputerDetail:
    computer: DirectoryComputer
    ou_manageable: bool
    ou_reason: str | None


@dataclass
class OuNode:
    dn: str
    name: str
    has_children: bool
    allowed: bool
    reason: str | None


def _clamp(v: int, lo: int, hi: int) -> int:
    return min(max(v, lo), hi)


def _short(v: str | None) -> str | None:
    return None if v is None or not v.strip() else v.strip()[:100]


# ====================================================================================== read side

class AdDirectoryService:
    """Talks to the directory provider and annotates results with allowlist and protection state."""

    def __init__(self, provider: DirectoryProvider, settings: AdSettingsService, user: CurrentUserInfo | None):
        self.provider = provider
        self.settings = settings
        self.user = user

    @property
    def role_scope(self) -> AdScope:
        """What the signed-in person's roles may manage (on top of the global allowlists)."""
        return self.user.ad_scope if self.user else AdScope()

    def search_users(self, q: str | None, flt: UserFilter, page: int, page_size: int, ou: str | None,
                     department: str | None = None, title: str | None = None) -> PagedResult[DirectoryUser]:
        s = self.settings.get()
        return self.provider.search_users(UserSearch(q, flt, max(1, page), _clamp(page_size, 1, 200), self._valid_ou(ou),
                                                     _clamp(s.search_result_limit, 50, 5000), s.read_options, _short(department), _short(title)))

    def get_user(self, id: uuid.UUID) -> UserDetail | None:
        s = self.settings.get()
        u = self.provider.get_user(id, s.read_options)
        if u is None:
            return None
        reason = (prot.ou_use_reason(u.ou, s.manageable_user_ous, s, self.provider.base_dn)
                  or prot.scope_ou_reason(self.role_scope, ObjectKind.User, u.ou))
        return UserDetail(u, reason is None, reason)

    def search_computers(self, q: str | None, flt: ComputerFilter, page: int, page_size: int, ou: str | None,
                         os_type: str | None = None) -> PagedResult[DirectoryComputer]:
        s = self.settings.get()
        os_key = os_type.strip().lower() if os_type and os_type_match(os_type) else None
        return self.provider.search_computers(ComputerSearch(q, flt, max(1, page), _clamp(page_size, 1, 200), self._valid_ou(ou),
                                                             _clamp(s.search_result_limit, 50, 5000), s.read_options, os_key))

    def get_computer(self, id: uuid.UUID) -> ComputerDetail | None:
        s = self.settings.get()
        c = self.provider.get_computer(id, s.read_options)
        if c is None:
            return None
        reason = (prot.ou_use_reason(c.ou, s.manageable_computer_ous, s, self.provider.base_dn)
                  or prot.scope_ou_reason(self.role_scope, ObjectKind.Computer, c.ou))
        return ComputerDetail(c, reason is None, reason)

    def search_groups(self, q: str | None, page: int, page_size: int) -> PagedResult[GroupDto]:
        s = self.settings.get()
        role = self.role_scope
        r = self.provider.search_groups(GroupSearch(q, max(1, page), _clamp(page_size, 1, 200), _clamp(s.search_result_limit, 50, 5000)))
        return PagedResult([GroupDto.from_group(g, s, role) for g in r.items], r.total, r.page, r.page_size, r.total_is_capped)

    def get_group(self, id: uuid.UUID) -> GroupDto | None:
        s = self.settings.get()
        g = self.provider.get_group(id)
        return None if g is None else GroupDto.from_group(g, s, self.role_scope)

    def get_memberships(self, id: uuid.UUID, kind: ObjectKind) -> MembershipsDto | None:
        s = self.settings.get()
        m = self.provider.get_memberships(id, kind)
        if m is None:
            return None
        role = self.role_scope
        return MembershipsDto(
            [GroupDto.from_group(g, s, role) for g in m.direct],
            [NestedGroupDto(GroupDto.from_group(n.group, s, role), n.via) for n in m.nested],
            None if m.primary is None else GroupDto.from_group(m.primary, s, role))

    def search_members(self, group_id: uuid.UUID, q: str | None, kind: MemberKind | None, page: int, page_size: int) -> PagedResult[GroupMember]:
        return self.provider.search_group_members(group_id, MemberSearch(q, kind, max(1, page), _clamp(page_size, 1, 500)))

    def browse_ous(self, parent: str | None, kind: ObjectKind, search: str | None) -> list[OuNode]:
        """Lazy OU tree: children of parent (or the domain root), marked with whether the object type may be moved there."""
        s = self.settings.get()
        found = (self.provider.browse_ous(self._valid_ou(parent)) if not search or not search.strip()
                 else self.provider.search_ous(search.strip(), 50))
        allow = prot.allowlist_for(kind, s)
        role = self.role_scope
        out = []
        for o in found:
            reason = prot.ou_use_reason(o.dn, allow, s, self.provider.base_dn) or prot.scope_ou_reason(role, kind, o.dn)
            # A parent that is not itself allowed may still contain allowed children, so it stays browsable.
            out.append(OuNode(o.dn, o.name, o.has_children, reason is None, reason))
        return out

    def _valid_ou(self, dn: str | None) -> str | None:
        return dn if dn and dn.strip() and is_valid_dn(dn) and is_under_or_equal(dn, self.provider.base_dn) else None


# ====================================================================================== role scope catalog

class AdScopeCatalogImpl:
    """The OUs and groups a role's scope can be chosen from: the global manageable lists on Settings > AD Integration."""

    def __init__(self, settings: AdSettingsService, provider: DirectoryProvider, user: CurrentUserInfo | None, directory: AdDirectoryService):
        self.settings = settings
        self.provider = provider
        self.user = user
        self.directory = directory

    def get_options(self) -> AdScopeOptions:
        s = self.settings.get()
        # Only what the signed-in person could hand out themselves (a limited manager cannot give a role more than their own reach).
        mine = self.user.ad_scope if self.user else AdScope()
        groups: list[AdScopeOption] = []
        for dn in [d for d in s.manageable_groups[:300] if prot.scope_group_reason(mine, d) is None]:
            g = self.provider.get_group_by_dn(dn)
            groups.append(AdScopeOption(dn, g.name if g else ou_label(dn)))

        def ous(dns: list[str], kind: ObjectKind) -> list[AdScopeOption]:
            return sorted((AdScopeOption(d, ou_label(d)) for d in dns if prot.scope_ou_reason(mine, kind, d) is None), key=lambda o: o.label.upper())

        return AdScopeOptions(ous(s.manageable_user_ous, ObjectKind.User), ous(s.manageable_computer_ous, ObjectKind.Computer),
                              sorted(groups, key=lambda o: o.label.upper()))

    @staticmethod
    def _kind_of(kind: str) -> ObjectKind | None:
        k = kind.lower()
        return ObjectKind.User if k == "users" else ObjectKind.Computer if k == "computers" else None

    def browse_ous(self, kind: str, parent_dn: str | None, search: str | None) -> list[AdScopeOuNode]:
        """The real OU tree, lazily, so every OU can be ticked. Same tree and rules as Move OU, so there is one place where
        "may this OU be used" is decided."""
        k = self._kind_of(kind)
        if k is None:
            raise ApiException(400, "Unknown kind", "Use users or computers.", "validation")
        return [AdScopeOuNode(n.dn, n.name, n.has_children, n.allowed, n.reason) for n in self.directory.browse_ous(parent_dn, k, search)]

    def is_selectable(self, kind: str, dn: str) -> bool:
        if not dn or not dn.strip() or not is_valid_dn(dn):
            return False
        s = self.settings.get()
        if kind.lower() == "groups":
            return any(dn_equal(g, dn) for g in s.manageable_groups)
        k = self._kind_of(kind)
        if k is None:
            return False
        if not is_under_or_equal(dn, self.provider.base_dn):
            return False
        if prot.ou_use_reason(dn, prot.allowlist_for(k, s), s, self.provider.base_dn) is not None:
            return False
        return self.provider.get_ou(dn) is not None  # the OU must exist: a made-up name under an allowed OU manages nothing


# ====================================================================================== change pipeline

@dataclass
class ChangeInput:
    """What every AD change request carries. Justification and ticket are checked against the Action Policies."""

    justification: str | None = None
    ticket_number: str | None = None
    typed_confirmation: str | None = None  # the account or computer name typed by the user, when the action policy asks for it
    validate_only: bool = False  # run the dry run only ("Validate only"): find the target, check rights, write nothing

    @staticmethod
    def _text(d: dict, key: str) -> str | None:
        v = d.get(key)
        return v if isinstance(v, str) else None

    @classmethod
    def from_dict(cls, d: dict | None):
        d = d or {}
        return cls(cls._text(d, "justification"), cls._text(d, "ticketNumber"), cls._text(d, "typedConfirmation"), d.get("validateOnly") is True)


@dataclass
class ResetPasswordRequest(ChangeInput):
    new_password: str | None = None
    must_change_at_next_sign_in: bool = False
    unlock_account: bool = False

    @classmethod
    def from_dict(cls, d: dict | None):
        d = d or {}
        base = ChangeInput.from_dict(d)
        return cls(base.justification, base.ticket_number, base.typed_confirmation, base.validate_only, cls._text(d, "newPassword"),
                   d.get("mustChangeAtNextSignIn") is True, d.get("unlockAccount") is True)

    def __repr__(self) -> str:  # a dataclass repr would print the password if this object were ever logged
        return "ResetPasswordRequest"


@dataclass
class MoveRequest(ChangeInput):
    target_ou: str | None = None

    @classmethod
    def from_dict(cls, d: dict | None):
        base = ChangeInput.from_dict(d)
        return cls(base.justification, base.ticket_number, base.typed_confirmation, base.validate_only, cls._text(d or {}, "targetOu"))


def _guid_list(d: dict | None, key: str) -> list[uuid.UUID] | None:
    v = (d or {}).get(key)
    if v is None:
        return None
    if not isinstance(v, list):
        raise ApiException(400, "Invalid request", f"'{key}' must be a list of ids.", "validation")
    out = []
    for x in v:
        try:
            out.append(uuid.UUID(str(x)))
        except ValueError:
            raise ApiException(400, "Invalid request", f"'{x}' is not a valid id.", "validation") from None
    return out


@dataclass
class GroupsRequest(ChangeInput):
    group_ids: list[uuid.UUID] | None = None

    @classmethod
    def from_dict(cls, d: dict | None):
        base = ChangeInput.from_dict(d)
        return cls(base.justification, base.ticket_number, base.typed_confirmation, base.validate_only, _guid_list(d, "groupIds"))


@dataclass
class GroupMembersRequest(ChangeInput):
    """Adds or removes several users from one group (the Groups page), as opposed to one user from several groups."""

    user_ids: list[uuid.UUID] | None = None

    @classmethod
    def from_dict(cls, d: dict | None):
        base = ChangeInput.from_dict(d)
        return cls(base.justification, base.ticket_number, base.typed_confirmation, base.validate_only, _guid_list(d, "userIds"))


SUCCESS, NO_CHANGE, FAILED, DENIED, VALIDATED = "Success", "NoChange", "Failed", "Denied", "Validated"


@dataclass
class ChangeResult:
    status: str
    message: str
    correlation_id: str
    action: str
    target: str
    error_code: str | None
    changes: list[DirectoryChange]
    checks: list[DryRunCheck]
    dry_run: bool
    group_id: uuid.UUID | None = None
    group_name: str | None = None

    @property
    def is_ok(self) -> bool:
        return self.status in (SUCCESS, NO_CHANGE, VALIDATED)

    @property
    def http_status(self) -> int:
        """Success, NoChange and Validated are 200; a denial is 403; a failed change or failed validation is 422."""
        return 403 if self.status == DENIED else 422 if self.status == FAILED else 200


@dataclass
class ChangeTarget:
    """The object being changed, freshly read from the directory for this request."""

    id: uuid.UUID
    kind: ObjectKind
    label: str
    ou: str
    user: DirectoryUser | None
    computer: DirectoryComputer | None
    settings: AdSettings


@dataclass
class ChangeSpec:
    action: str
    policy_key: str
    permission: str
    target_id: uuid.UUID
    kind: ObjectKind
    input: ChangeInput
    check: object  # (ChangeTarget) -> str | None: allowlist and protected-object rules, applied to the fresh data
    describe: object  # (ChangeTarget) -> list[DirectoryChange] | None: the intended change; None = nothing to change
    apply: object  # (dry_run: bool) -> DirectoryResult
    no_change_message: str | None = None
    group_id: uuid.UUID | None = None
    group_name: str | None = None


class AdChangeService:
    """The one place where every AD change happens: permission, input checks, fresh re-read, allowlists, dry run,
    the change itself, audit, and a result with a correlation ID."""

    def __init__(self, provider: DirectoryProvider, ad_settings: AdSettingsService, settings, user: CurrentUserInfo | None, audit):
        self.provider = provider
        self.ad_settings = ad_settings
        self.settings = settings
        self.user = user
        self.audit = audit
        self._scope = AdScope()  # what the signed-in person's roles may manage (set at the start of every change)

    # ================================================================== the shared pipeline

    def run(self, spec: ChangeSpec) -> ChangeResult:
        user = self.user
        if user is None:
            raise ApiException(401, "Not signed in", "Sign in to continue.", "unauthenticated")
        self._scope = user.ad_scope
        inp = spec.input
        target_text = str(spec.target_id)

        # 1. Permission (the endpoint policy already checked; this is the defence in depth for every caller of the service).
        if not user.has(spec.permission):
            return self._denied(spec, target_text, "You do not have permission to do this.", inp)

        # 2. Validate the input against the Action Policies.
        policies = self.settings.action_policies()
        policy = policies.actions.get(spec.policy_key) or ActionPolicy()
        self._validate_input(policy, inp)

        # 3. Re-read the object's current state from AD.
        s = self.ad_settings.get()
        try:
            target = self._read_target(spec, s)
        except ModuleUnavailableError:
            self._record(spec, target_text, AuditResult.FAILURE, "The directory could not be reached", None, inp)
            raise
        if target is None:
            return self._finish(spec, target_text, FAILED, DirectoryErrors.NOT_FOUND, "The object no longer exists in the directory.", [], [], False,
                                AuditResult.FAILURE, inp, None)
        target_text = target.label

        if policy.typed_confirmation_required and not inp.validate_only:
            expected = (target.user.sam_account_name if target.user else target.computer.name if target.computer else "")
            if (inp.typed_confirmation or "").strip().upper() != expected.upper():
                raise ApiException(400, "Confirmation does not match", f"Type {expected} exactly to confirm.", "validation")

        # 4. Allowlists and protected objects, against the fresh data.
        denial = spec.check(target)
        if denial:
            return self._denied(spec, target_text, denial, inp)

        changes = spec.describe(target)
        if changes is None:
            return self._finish(spec, target_text, NO_CHANGE, None, spec.no_change_message or "Already in the requested state. No change was made.",
                                [], [], False, AuditResult.SUCCESS, inp, "No change needed")

        # 5. Dry run through the provider. If it fails, stop.
        try:
            dry: DirectoryResult = spec.apply(True)
        except ModuleUnavailableError:
            self._record(spec, target_text, AuditResult.FAILURE, "The directory could not be reached", changes, inp)
            raise
        if not dry.success:
            return self._finish(spec, target_text, FAILED, dry.error_code, "Validation failed: " + (dry.message or ""), changes, dry.checks, True,
                                AuditResult.FAILURE, inp, dry.message)

        # A requested dry run (the confirmation preview or the Validate button) is recorded once. The automatic check that runs
        # inside a real change is not recorded separately: the change's own result row already says what happened.
        if inp.validate_only:
            self._record(spec, target_text, AuditResult.VALIDATED, None, changes, inp)
            return self._result(spec, target_text, VALIDATED, None, "Validated. No change was made.", changes, dry.checks, True)

        # 6. The change itself.
        try:
            done: DirectoryResult = spec.apply(False)
        except ModuleUnavailableError:
            self._record(spec, target_text, AuditResult.FAILURE, "The directory could not be reached", changes, inp)
            raise

        # 7 + 8. Audit the outcome and return it with the correlation ID.
        if done.success:
            return self._finish(spec, target_text, SUCCESS, None, "The change was made.", changes, dry.checks, False, AuditResult.SUCCESS, inp, None)
        return self._finish(spec, target_text, FAILED, done.error_code, done.message or "The directory refused the change.", changes, dry.checks, False,
                            AuditResult.FAILURE, inp, done.message)

    def _read_target(self, spec: ChangeSpec, s: AdSettings) -> ChangeTarget | None:
        o = s.read_options
        if spec.kind == ObjectKind.User:
            u = self.provider.get_user(spec.target_id, o)
            return None if u is None else ChangeTarget(u.id, spec.kind, f"{u.sam_account_name} ({u.display_name or u.sam_account_name})", u.ou, u, None, s)
        c = self.provider.get_computer(spec.target_id, o)
        return None if c is None else ChangeTarget(c.id, spec.kind, c.name, c.ou, None, c, s)

    @staticmethod
    def _validate_input(policy: ActionPolicy, inp: ChangeInput) -> None:
        justification = (inp.justification or "").strip()
        need = max(1, policy.justification_min_length)
        if policy.justification_required and len(justification) < need:
            raise ApiException(400, "Justification required", f"Enter a justification of at least {need} characters.", "validation")
        if len(justification) > 2000:
            raise ApiException(400, "Justification too long", "The justification can be up to 2000 characters.", "validation")

        ticket = (inp.ticket_number or "").strip()
        if policy.ticket_required and not ticket:
            raise ApiException(400, "Ticket number required", "Enter the ticket number for this change.", "validation")
        if len(ticket) > 100:
            raise ApiException(400, "Ticket number too long", "The ticket number can be up to 100 characters.", "validation")
        if ticket and policy.ticket_pattern and policy.ticket_pattern.strip():
            try:
                ok = regex.search(policy.ticket_pattern, ticket, timeout=0.25) is not None
            except TimeoutError:
                ok = False
            except regex.error:
                ok = True  # a broken pattern in Settings must not lock everyone out; it is validated on save
            if not ok:
                raise ApiException(400, "Ticket number format", "The ticket number does not match the required format.", "validation")

    # ---------- outcome helpers ----------

    def _result(self, spec: ChangeSpec, target: str, status: str, code: str | None, message: str, changes: list, checks: list, dry_run: bool) -> ChangeResult:
        return ChangeResult(status, message, correlation_id(), spec.action, target, code, list(changes), list(checks), dry_run, spec.group_id, spec.group_name)

    def _denied(self, spec: ChangeSpec, target: str, reason: str, inp: ChangeInput) -> ChangeResult:
        self._record(spec, target, AuditResult.DENIED, reason, None, inp)
        return self._result(spec, target, DENIED, "denied", reason, [], [], False)

    def _finish(self, spec, target, status, code, message, changes, checks, dry_run, audit_result, inp, audit_error) -> ChangeResult:
        self._record(spec, target, audit_result, audit_error, changes, inp)
        return self._result(spec, target, status, code, message, changes, checks, dry_run)

    def _record(self, spec: ChangeSpec, target: str, result: str, error: str | None, changes: list[DirectoryChange] | None, inp: ChangeInput) -> None:
        self.audit.write(AuditEntry(
            action=spec.action, module=MODULE_ID,
            target=target if spec.group_name is None else f"{target} / group {spec.group_name}",
            target_id=str(spec.target_id),
            previous_value="; ".join(f"{c.field}: {c.from_ if c.from_ is not None else '-'}" for c in changes) if changes else None,
            new_value="; ".join(f"{c.field}: {c.to if c.to is not None else '-'}" for c in changes) if changes else None,
            result=result, error=error,
            justification=(inp.justification or "").strip() if inp.justification is not None else None,
            ticket_number=(inp.ticket_number or "").strip() if inp.ticket_number is not None else None))

    # ================================================================== the actions

    @staticmethod
    def _protected_account(t: ChangeTarget) -> str | None:
        return ("This account is marked as protected (adminCount=1) and cannot be changed in this application."
                if t.user is not None and t.user.admin_count else None)

    def _ou_check(self, t: ChangeTarget) -> str | None:
        allow = prot.allowlist_for(t.kind, t.settings)
        return prot.ou_use_reason(t.ou, allow, t.settings, self.provider.base_dn) or prot.scope_ou_reason(self._scope, t.kind, t.ou)

    def _user_ou_check(self, t: ChangeTarget) -> str | None:
        return self._protected_account(t) or self._ou_check(t)

    def reset_password(self, user_id: uuid.UUID, req: ResetPasswordRequest) -> ChangeResult:
        password = None
        if not req.validate_only:
            if not req.new_password:
                raise ApiException(400, "Password required", "Enter the new password.", "validation")
            if len(req.new_password) > 256:
                raise ApiException(400, "Password too long", "The password is too long.", "validation")
            password = req.new_password
        req.new_password = None  # the request object no longer holds the password
        options = ResetPasswordOptions(req.must_change_at_next_sign_in, req.unlock_account)

        def check(t: ChangeTarget) -> str | None:
            # "Also unlock the account" is an unlock, so it needs the unlock right as well as the reset right.
            if options.unlock_account and self.user is not None and not self.user.has(P.AD_USERS_UNLOCK):
                return "Unlocking the account as part of a password reset needs the unlock permission, which you do not have."
            return self._user_ou_check(t)

        def describe(t: ChangeTarget):
            u = t.user
            return [
                DirectoryChange("Password", "Current password (not shown)", "New password (not shown)"),
                DirectoryChange("Must change password at next sign-in", "Yes" if u.password_status == "MustChange" else "No",
                                "Yes" if options.must_change_at_next_sign_in else "No"),
                DirectoryChange("Account unlock", "Locked" if u.locked_out else "Not locked",
                                "Not locked" if not u.locked_out else "Unlocked" if options.unlock_account else "Stays locked"),
            ]

        # A dry run never sends a password to AD: only the target and the right to reset are checked.
        return self.run(ChangeSpec(
            "ad.user.resetPassword", ActionKeys.RESET_PASSWORD, P.AD_USERS_RESET_PASSWORD, user_id, ObjectKind.User, req, check, describe,
            lambda dry: self.provider.reset_password(user_id, password or "", options, dry)))

    def unlock(self, user_id: uuid.UUID, req: ChangeInput) -> ChangeResult:
        return self.run(ChangeSpec(
            "ad.user.unlock", ActionKeys.UNLOCK, P.AD_USERS_UNLOCK, user_id, ObjectKind.User, req, self._user_ou_check,
            # Re-checked against the fresh read: if the lockout has already passed, nothing is changed.
            lambda t: [DirectoryChange("Locked out", "Yes", "No")] if t.user.locked_out else None,
            lambda dry: self.provider.unlock(user_id, dry),
            no_change_message="The account is no longer locked. No change was made."))

    def set_user_enabled(self, user_id: uuid.UUID, enable: bool, req: ChangeInput) -> ChangeResult:
        return self.run(ChangeSpec(
            "ad.user.enable" if enable else "ad.user.disable", ActionKeys.ENABLE_USER if enable else ActionKeys.DISABLE_USER,
            P.AD_USERS_ENABLE if enable else P.AD_USERS_DISABLE, user_id, ObjectKind.User, req, self._user_ou_check,
            lambda t: None if t.user.enabled == enable else [DirectoryChange("Account", "Enabled" if t.user.enabled else "Disabled", "Enabled" if enable else "Disabled")],
            lambda dry: self.provider.set_enabled(user_id, ObjectKind.User, enable, dry),
            no_change_message="The account is already enabled. No change was made." if enable else "The account is already disabled. No change was made."))

    def set_computer_enabled(self, computer_id: uuid.UUID, enable: bool, req: ChangeInput) -> ChangeResult:
        return self.run(ChangeSpec(
            "ad.computer.enable" if enable else "ad.computer.disable", ActionKeys.ENABLE_COMPUTER if enable else ActionKeys.DISABLE_COMPUTER,
            P.AD_COMPUTERS_ENABLE if enable else P.AD_COMPUTERS_DISABLE, computer_id, ObjectKind.Computer, req, self._ou_check,
            lambda t: None if t.computer.enabled == enable else [DirectoryChange("Computer account", "Enabled" if t.computer.enabled else "Disabled", "Enabled" if enable else "Disabled")],
            lambda dry: self.provider.set_enabled(computer_id, ObjectKind.Computer, enable, dry),
            no_change_message="The computer is already enabled. No change was made." if enable else "The computer is already disabled. No change was made."))

    def move(self, id: uuid.UUID, kind: ObjectKind, req: MoveRequest) -> ChangeResult:
        target = (req.target_ou or "").strip()
        if not is_valid_dn(target) or not is_under_or_equal(target, self.provider.base_dn):
            raise ApiException(400, "Invalid target OU", "Choose a target OU from the tree.", "validation")
        user = kind == ObjectKind.User

        def check(t: ChangeTarget) -> str | None:
            p = self._protected_account(t)
            if p:
                return p
            allow = prot.allowlist_for(kind, t.settings)
            # Both the current OU and the target OU must be allowed and not blocked.
            cur = prot.ou_use_reason(t.ou, allow, t.settings, self.provider.base_dn)
            if cur:
                return "Current location: " + cur
            tgt = prot.ou_use_reason(target, allow, t.settings, self.provider.base_dn)
            if tgt:
                return "Target: " + tgt
            cur_scope = prot.scope_ou_reason(self._scope, kind, t.ou)
            if cur_scope:
                return "Current location: " + cur_scope
            tgt_scope = prot.scope_ou_reason(self._scope, kind, target)
            if tgt_scope:
                return "Target: " + tgt_scope
            if self.provider.get_ou(target) is None:
                return "The target OU does not exist."
            return None

        return self.run(ChangeSpec(
            "ad.user.move" if user else "ad.computer.move", ActionKeys.MOVE_USER if user else ActionKeys.MOVE_COMPUTER,
            P.AD_USERS_MOVE if user else P.AD_COMPUTERS_MOVE, id, kind, req, check,
            lambda t: None if dn_equal(t.ou, target) else [DirectoryChange("OU", t.ou, target)],
            lambda dry: self.provider.move(id, kind, target, dry),
            no_change_message="The object is already in that OU. No change was made."))

    def change_groups(self, user_id: uuid.UUID, add: bool, req: GroupsRequest) -> list[ChangeResult]:
        """Adds or removes the user from each group in turn. Every group goes through the full pipeline and is reported separately."""
        ids = list(dict.fromkeys(req.group_ids or []))
        if not ids:
            raise ApiException(400, "No groups selected", "Select at least one group.", "validation")
        if len(ids) > 50:
            raise ApiException(400, "Too many groups", "Select up to 50 groups at a time.", "validation")

        results = []
        for gid in ids:
            group = self.provider.get_group(gid)
            name = group.name if group else str(gid)

            def check(t: ChangeTarget, gid=gid) -> str | None:
                p = self._protected_account(t)
                if p:
                    return p
                ou = self._ou_check(t)
                if ou:
                    return ou
                # Re-read the group too: protection and the allowlist are checked on fresh data, never on what the browser sent.
                fresh = self.provider.get_group(gid)
                if fresh is None:
                    return "The group no longer exists."
                g = prot.group_block_reason(fresh, t.settings)
                if g:
                    return g
                gs = prot.scope_group_reason(self._scope, fresh.dn)
                if gs:
                    return gs
                if not add:
                    m = self.provider.get_memberships(user_id, ObjectKind.User)
                    if m is not None and m.primary is not None and m.primary.id == gid:
                        return "The primary group cannot be removed."
                return None

            results.append(self.run(ChangeSpec(
                "ad.user.groups.add" if add else "ad.user.groups.remove",
                ActionKeys.ADD_TO_GROUPS if add else ActionKeys.REMOVE_FROM_GROUPS,
                P.AD_USERS_GROUPS_ADD if add else P.AD_USERS_GROUPS_REMOVE, user_id, ObjectKind.User, req, check,
                lambda t, name=name: [DirectoryChange("Group membership: " + name, "Not a member" if add else "Member", "Member" if add else "Not a member")],
                (lambda dry, gid=gid: self.provider.add_to_groups(user_id, [gid], dry)) if add
                else (lambda dry, gid=gid: self.provider.remove_from_groups(user_id, [gid], dry)),
                group_id=gid, group_name=name)))
        return results

    def change_group_members(self, group_id: uuid.UUID, add: bool, req: GroupMembersRequest) -> list[ChangeResult]:
        """Adds or removes several users from one group. Each user goes through exactly the same pipeline as from the user's own
        Groups tab and is reported separately."""
        ids = list(dict.fromkeys(req.user_ids or []))
        if not ids:
            raise ApiException(400, "No users selected", "Select at least one user.", "validation")
        if len(ids) > 50:
            raise ApiException(400, "Too many users", "Select up to 50 users at a time.", "validation")

        group = self.provider.get_group(group_id)
        if group is None:
            raise ApiException(404, "Not found", "Group not found in the directory.", "not_found")
        # From the Groups page the thing being changed is the group, so the typed confirmation is the group's name (checked once here).
        policies = self.settings.action_policies()
        policy = policies.actions.get(ActionKeys.ADD_TO_GROUPS if add else ActionKeys.REMOVE_FROM_GROUPS)
        if (policy is not None and policy.typed_confirmation_required and not req.validate_only
                and (req.typed_confirmation or "").strip().upper() != group.name.upper()):
            raise ApiException(400, "Confirmation does not match", f"Type {group.name} exactly to confirm.", "validation")

        results: list[ChangeResult] = []
        for user_id in ids:
            u = self.provider.get_user(user_id, self.ad_settings.get().read_options)
            per_user = GroupsRequest(req.justification, req.ticket_number, u.sam_account_name if u else None, req.validate_only, [group_id])
            results += self.change_groups(user_id, add, per_user)  # already confirmed against the group name above
        return results

    def addable_groups(self, user_id: uuid.UUID, q: str | None) -> list[dict]:
        """The groups a user could be added to: the manageable allowlist, minus protected groups, flagged if already a member."""
        s = self.ad_settings.get()
        memberships = self.provider.get_memberships(user_id, ObjectKind.User)
        if memberships is None:
            raise ApiException(404, "Not found", "User not found in the directory.", "not_found")
        scope = self.user.ad_scope if self.user else AdScope()
        direct = {g.id for g in memberships.direct}
        primary = memberships.primary.id if memberships.primary else None
        text = (q or "").strip().lower()
        out = []
        for dn in s.manageable_groups[:300]:
            g = self.provider.get_group_by_dn(dn)
            if g is None:
                continue
            if text and text not in g.name.lower() and text not in (g.description or "").lower():
                continue
            if prot.is_group_protected(g, s) or prot.scope_group_reason(scope, g.dn) is not None:
                continue
            out.append(g)
        out.sort(key=lambda g: g.name.upper())
        return [{"id": g.id, "name": g.name, "description": g.description, "scope": g.scope, "type": g.type,
                 "alreadyMember": g.id in direct or primary == g.id} for g in out]


# ====================================================================================== wiring per request

@dataclass
class AdServices:
    settings: AdSettingsService
    directory: AdDirectoryService
    changes: AdChangeService


def ad_services(ctx: Ctx) -> AdServices:
    cached = getattr(ctx, "_ad_services", None)
    if cached is None:
        user = ctx.user()
        provider = ctx.state.provider
        settings = AdSettingsService(ctx.settings, provider)
        directory = AdDirectoryService(provider, settings, user)
        cached = AdServices(settings, directory, AdChangeService(provider, settings, ctx.settings, user, ctx.audit))
        ctx._ad_services = cached
    return cached


def build_scope_catalog(ctx: Ctx) -> AdScopeCatalogImpl:
    svc = ad_services(ctx)
    return AdScopeCatalogImpl(svc.settings, ctx.state.provider, ctx.user(), svc.directory)


# ====================================================================================== search and dashboard hooks

PER_CATEGORY = 5


@dataclass
class _Counts:
    locked: int
    disabled: int
    expired: int
    disabled_computers: int
    updated: datetime
    expires_at: float = 0.0


class AdHooks:
    """What the AD module contributes to the core: global search results and Home cards."""

    module_id = MODULE_ID

    def __init__(self) -> None:
        self._gate = threading.Lock()  # one refresh at a time across all requests, so a burst of loads runs the directory queries once
        self._counts: _Counts | None = None

    # ---- search

    def search(self, ctx: Ctx, query: str, user: CurrentUserInfo) -> list[dict]:
        svc = ad_services(ctx)
        ad = svc.directory
        enc = quote(query, safe="")
        out: list[dict] = []
        if user.has(P.AD_USERS_READ):
            r = ad.search_users(query, UserFilter.All, 1, PER_CATEGORY, None)
            out.append(_category("users", "Users", [
                _item(u.id, u.display_name or u.sam_account_name, f"{u.sam_account_name} - {ou_label(u.ou)}",
                      _tags(None if u.enabled else "Disabled", "Locked" if u.locked_out else None), f"/ad/users/{u.id}") for u in r.items],
                r.total, r.total_is_capped, f"/ad/users?q={enc}"))
        if user.has(P.AD_COMPUTERS_READ):
            r = ad.search_computers(query, ComputerFilter.All, 1, PER_CATEGORY, None)
            out.append(_category("computers", "Computers", [
                _item(c.id, c.name, f"{c.dns_host_name or c.operating_system} - {ou_label(c.ou)}",
                      _tags(None if c.enabled else "Disabled"), f"/ad/computers/{c.id}") for c in r.items],
                r.total, r.total_is_capped, f"/ad/computers?q={enc}"))
        if user.has(P.AD_GROUPS_READ):
            g = ad.search_groups(query, 1, PER_CATEGORY)
            out.append(_category("groups", "Groups", [
                _item(x.id, x.name, x.description, _tags("Protected" if x.is_protected else None), f"/ad/groups/{x.id}") for x in g.items],
                g.total, g.total_is_capped, f"/ad/groups?q={enc}"))
        return out

    # ---- dashboard cards

    def dashboard_cards(self, ctx: Ctx, user: CurrentUserInfo) -> list[dict]:
        wants_users = user.has(P.AD_USERS_READ)
        wants_computers = user.has(P.AD_COMPUTERS_READ)
        if not wants_users and not wants_computers:
            return []
        c = self._get_counts(ctx)
        up = c.updated
        cards = []
        if wants_users:
            # "Locked" is confirmed with msDS-User-Account-Control-Computed by the provider, not just an old lockoutTime.
            cards.append(_card("lockedUsers", "Locked users", c.locked, "/ad/users?filter=Locked", "warning", up))
            cards.append(_card("disabledUsers", "Disabled users", c.disabled, "/ad/users?filter=Disabled", "neutral", up))
            cards.append(_card("expiredUsers", "Expired user accounts", c.expired, "/ad/users?filter=AccountExpired", "warning", up))
        if wants_computers:
            cards.append(_card("disabledComputers", "Disabled computers", c.disabled_computers, "/ad/computers?filter=Disabled", "neutral", up))
        return cards

    def _get_counts(self, ctx: Ctx) -> _Counts:
        hit = self._counts
        if hit is not None and time.monotonic() < hit.expires_at:
            return hit
        with self._gate:
            hit = self._counts
            if hit is not None and time.monotonic() < hit.expires_at:
                return hit
            p = ctx.state.provider
            counts = _Counts(p.count_users(UserFilter.Locked), p.count_users(UserFilter.Disabled), p.count_users(UserFilter.AccountExpired),
                             p.count_computers(ComputerFilter.Disabled), utcnow())
            minutes = ctx.config.app.dashboard_cache_minutes
            counts.expires_at = time.monotonic() + minutes * 60 if minutes > 0 else 0.0
            self._counts = counts
            return counts


def _tags(*tags: str | None) -> list[str]:
    return [t for t in tags if t]


def _item(id_, title, subtitle, tags, route) -> dict:
    return {"id": str(id_), "title": title, "subtitle": subtitle, "tags": tags, "route": route}


def _category(key, label, items, total, capped, see_all) -> dict:
    return {"key": key, "label": label, "items": items, "total": total, "totalIsCapped": capped, "seeAllRoute": see_all}


def _card(key, title, count, route, tone, updated) -> dict:
    from ...util import iso

    return {"key": key, "title": title, "count": count, "route": route, "tone": tone, "updatedUtc": iso(updated)}
