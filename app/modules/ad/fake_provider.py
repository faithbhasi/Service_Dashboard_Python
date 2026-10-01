"""In-memory Active Directory for local development and tests.

Implements the same interface as the LDAP provider, including dry runs, and shares the account-status logic with it.
Nothing is persisted: restart to reset.
"""
from __future__ import annotations

import sys
import threading
import uuid
from collections import deque
from datetime import datetime, timedelta

from ...util import utcnow
from . import fake_data as fd
from . import user_status as us
from .dn import dn_equal, is_under_or_equal, parent_dn, split_rdns
from .provider import (
    COMPUTER_OS_TYPES, ComputerFilter, ComputerSearch, ConnectionStep, ConnectionTestResult, DirectoryChange, DirectoryComputer,
    DirectoryErrors, DirectoryGroup, DirectoryOu, DirectoryResult, DirectoryUnavailableError, DirectoryUser, DryRunCheck, GroupMember,
    GroupSearch, MemberKind, MemberSearch, Memberships, NestedMembership, ObjectKind, ObjectRef, PagedResult, ReadOptions,
    ResetPasswordOptions, SuggestedAllowlists, UserFilter, UserSearch, os_type_match,
)


class FakeSimulation:
    """Switches for the error simulations the Fake provider supports."""

    def __init__(self, server_unavailable: bool = False):
        # Every call raises DirectoryUnavailableError, as if the domain controller were down.
        self.server_unavailable = server_unavailable


def _has(value: str | None, t: str) -> bool:
    return value is not None and t.lower() in value.lower()


def _page(all_items: list, page: int, page_size: int, limit: int) -> tuple[list, int, int, int, bool]:
    capped = len(all_items) > limit
    total = limit if capped else len(all_items)
    page_size = max(1, page_size)
    page = max(1, page)
    items = all_items[:limit][(page - 1) * page_size:(page - 1) * page_size + page_size]
    return items, total, page, page_size, capped


def _ou_name(dn: str) -> str:
    first = split_rdns(dn)[0]
    return first[first.index("=") + 1:]


class FakeDirectoryProvider:
    provider_name = "Fake"
    base_dn = fd.BASE

    def __init__(self, simulate_server_unavailable: bool = False):
        self._d = fd.seed()
        self._lock = threading.RLock()
        self.simulation = FakeSimulation(simulate_server_unavailable)

    @property
    def suggested_defaults(self) -> SuggestedAllowlists:
        return SuggestedAllowlists(
            user_ous=[fd.STAFF, fd.CONTRACTORS],
            computer_ous=[fd.WORKSTATIONS, fd.LAPTOPS],
            manageable_groups=[g.dn for g in self._d.groups if g.ou == fd.GROUPS_OU and not g.admin_count],
            protected_groups=[],
        )

    def _guard(self) -> None:
        if self.simulation.server_unavailable:
            raise DirectoryUnavailableError("Simulated: domain controller unreachable")

    # ------------------------------------------------------------------ mapping

    def _ref(self, id_: uuid.UUID | None) -> ObjectRef | None:
        if id_ is None:
            return None
        u = next((x for x in self._d.users if x.id == id_), None)
        if u:
            return ObjectRef(u.id, u.display or u.sam, ObjectKind.User)
        g = next((x for x in self._d.groups if x.id == id_), None)
        if g:
            return ObjectRef(g.id, g.name, ObjectKind.Group)
        c = next((x for x in self._d.computers if x.id == id_), None)
        return ObjectRef(c.id, c.name, ObjectKind.Computer) if c else None

    def _to_user(self, u: fd.FakeUser, o: ReadOptions) -> DirectoryUser:
        now = utcnow()
        max_age = timedelta(days=u.pso_max_age_days if u.pso_max_age_days > 0 else 90)
        if u.uac & us.DONT_EXPIRE_PASSWORD:
            expiry = us.NEVER_FILETIME
        elif u.pwd_last_set == 0:
            expiry = 0
        else:
            expiry = us.to_filetime(us.from_filetime(u.pwd_last_set) + max_age)
        computed = 0
        if u.locked_out:
            computed |= us.COMPUTED_LOCKOUT
        if 0 < expiry < us.NEVER_FILETIME and us.from_filetime(expiry) <= now and not u.uac & us.DONT_EXPIRE_PASSWORD:
            computed |= us.COMPUTED_PASSWORD_EXPIRED
        ae_kind, ae_date = us.account_expiry(u.account_expires, now)
        pw_status, pw_date = us.password(u.uac, computed, u.pwd_last_set, expiry, now)
        uac = u.uac | (us.LOCKOUT if u.locked_out else 0)
        return DirectoryUser(
            id=u.id, dn=u.dn, ou=u.ou, sam_account_name=u.sam, user_principal_name=u.sam + "@fake.local",
            display_name=u.display, given_name=u.given, surname=u.surname, email=u.email,
            employee_id=u.employee if o.employee_id_attribute.lower() == "employeeid" else None,
            title=u.title, department=u.department, office=u.office, phone=u.phone, mobile=u.mobile, description=u.description,
            manager=self._ref(u.manager), enabled=us.is_enabled(u.uac), locked_out=us.is_locked_out(computed),
            account_expiry=ae_kind, account_expires_utc=ae_date, password_status=pw_status, password_expires_utc=pw_date,
            password_last_set_utc=None if u.pwd_last_set == 0 else us.from_filetime(u.pwd_last_set),
            last_logon_utc=u.last_logon, created_utc=u.created, changed_utc=u.changed,
            resultant_pso=u.pso, user_account_control=uac, uac_flags=us.describe_flags(uac),
            primary_group_id=513, admin_count=u.admin_count,
        )

    def _to_computer(self, c: fd.FakeComputer, o: ReadOptions) -> DirectoryComputer:
        last_user = None
        if o.computer_last_user_attribute and o.computer_last_user_attribute.strip() and o.computer_last_user_attribute.lower() == "description":
            last_user = c.description
        return DirectoryComputer(
            id=c.id, dn=c.dn, ou=c.ou, name=c.name, dns_host_name=c.name.lower() + ".fake.local", enabled=not c.disabled,
            operating_system=c.os, os_version=c.os_version, last_logon_utc=c.last_logon, password_last_set_utc=c.pwd_last_set,
            managed_by=self._ref(c.managed_by), description=c.description, changed_utc=c.changed, created_utc=c.created,
            last_logged_in_user=last_user,
        )

    def _to_group(self, g: fd.FakeGroup, with_count: bool = False) -> DirectoryGroup:
        return DirectoryGroup(
            id=g.id, dn=g.dn, ou=g.ou, name=g.name, description=g.description, scope=g.scope, type=g.type,
            managed_by=self._ref(g.managed_by), admin_count=g.admin_count, primary_group_token=g.token,
            member_count=len(self._d.members.get(g.id, ())) if with_count else None,
        )

    # ------------------------------------------------------------------ reads

    def search_users(self, s: UserSearch) -> PagedResult[DirectoryUser]:
        self._guard()
        with self._lock:
            now = utcnow()
            q = list(self._d.users)
            if s.text and s.text.strip():
                t = s.text.strip()
                q = [u for u in q if _has(u.sam, t) or _has(u.sam + "@fake.local", t) or _has(u.display, t) or _has(u.given, t)
                     or _has(u.surname, t) or _has(u.email, t) or _has(u.employee, t)]
            if s.ou_dn:
                q = [u for u in q if is_under_or_equal(u.ou, s.ou_dn)]
            if s.department and s.department.strip():
                q = [u for u in q if _has(u.department, s.department.strip())]
            if s.title and s.title.strip():
                q = [u for u in q if _has(u.title, s.title.strip())]
            if s.filter == UserFilter.Locked:
                q = [u for u in q if u.locked_out]
            elif s.filter == UserFilter.Disabled:
                q = [u for u in q if not us.is_enabled(u.uac)]
            elif s.filter == UserFilter.Enabled:
                q = [u for u in q if us.is_enabled(u.uac)]
            elif s.filter == UserFilter.AccountExpired:
                q = [u for u in q if us.account_expiry(u.account_expires, now)[0] == "Expired"]
            q.sort(key=lambda u: (u.display or u.sam).upper())
            items, total, page, size, capped = _page(q, s.page, s.page_size, s.limit)
            return PagedResult([self._to_user(u, s.options) for u in items], total, page, size, capped)

    def get_user(self, id: uuid.UUID, options: ReadOptions) -> DirectoryUser | None:
        self._guard()
        with self._lock:
            u = next((x for x in self._d.users if x.id == id), None)
            return self._to_user(u, options) if u else None

    def search_computers(self, s: ComputerSearch) -> PagedResult[DirectoryComputer]:
        self._guard()
        with self._lock:
            q = list(self._d.computers)
            if s.text and s.text.strip():
                t = s.text.strip()
                q = [c for c in q if _has(c.name, t) or _has(c.name + ".fake.local", t)]
            if s.ou_dn:
                q = [c for c in q if is_under_or_equal(c.ou, s.ou_dn)]
            os_matches = os_type_match(s.os_type)
            if os_matches:
                q = [c for c in q if any(_has(c.os, m) for m in os_matches)]
            if s.filter == ComputerFilter.Disabled:
                q = [c for c in q if c.disabled]
            elif s.filter == ComputerFilter.Enabled:
                q = [c for c in q if not c.disabled]
            q.sort(key=lambda c: c.name.upper())
            items, total, page, size, capped = _page(q, s.page, s.page_size, s.limit)
            return PagedResult([self._to_computer(c, s.options) for c in items], total, page, size, capped)

    def get_computer(self, id: uuid.UUID, options: ReadOptions) -> DirectoryComputer | None:
        self._guard()
        with self._lock:
            c = next((x for x in self._d.computers if x.id == id), None)
            return self._to_computer(c, options) if c else None

    def search_groups(self, s: GroupSearch) -> PagedResult[DirectoryGroup]:
        self._guard()
        with self._lock:
            q = list(self._d.groups)
            if s.text and s.text.strip():
                t = s.text.strip()
                q = [g for g in q if _has(g.name, t) or _has(g.description, t)]
            q.sort(key=lambda g: g.name.upper())
            items, total, page, size, capped = _page(q, s.page, s.page_size, s.limit)
            return PagedResult([self._to_group(g) for g in items], total, page, size, capped)

    def get_group(self, id: uuid.UUID) -> DirectoryGroup | None:
        self._guard()
        with self._lock:
            g = next((x for x in self._d.groups if x.id == id), None)
            return self._to_group(g, with_count=True) if g else None

    def get_group_by_dn(self, dn: str) -> DirectoryGroup | None:
        self._guard()
        with self._lock:
            g = next((x for x in self._d.groups if dn_equal(x.dn, dn)), None)
            return self._to_group(g) if g else None

    def _groups_of(self, member_id: uuid.UUID) -> list[fd.FakeGroup]:
        return [g for g in self._d.groups if member_id in self._d.members.get(g.id, ())]

    def get_memberships(self, object_id: uuid.UUID, kind: ObjectKind) -> Memberships | None:
        self._guard()
        with self._lock:
            if kind == ObjectKind.User:
                exists = any(u.id == object_id for u in self._d.users)
            else:
                exists = any(c.id == object_id for c in self._d.computers)
            if not exists:
                return None
            primary = self._d.group("Domain Users" if kind == ObjectKind.User else "Domain Computers")
            # Primary group membership is not stored in "member": show it once, as the primary group.
            direct = sorted((g for g in self._groups_of(object_id) if g.id != primary.id), key=lambda g: g.name.lower())
            direct_ids = {g.id for g in direct}
            nested: dict[uuid.UUID, NestedMembership] = {}
            for d in direct:
                queue = deque([d])
                seen = {d.id}
                while queue:
                    for parent in self._groups_of(queue.popleft().id):
                        if parent.id in seen:
                            continue
                        seen.add(parent.id)
                        queue.append(parent)
                        if parent.id not in direct_ids and parent.id not in nested:
                            nested[parent.id] = NestedMembership(self._to_group(parent), d.name)
            return Memberships(
                direct=[self._to_group(g) for g in direct],
                nested=sorted(nested.values(), key=lambda n: n.group.name.lower()),
                primary=self._to_group(primary),
            )

    def search_group_members(self, group_id: uuid.UUID, s: MemberSearch) -> PagedResult[GroupMember]:
        self._guard()
        with self._lock:
            ids = self._d.members.get(group_id, set())
            t = s.text.strip() if s.text else None
            users = {u.id: u for u in self._d.users}
            computers = {c.id: c for c in self._d.computers}
            groups = {g.id: g for g in self._d.groups}
            matches: list[GroupMember] = []
            for id_ in ids:
                if id_ in users:
                    u = users[id_]
                    m = GroupMember(u.id, MemberKind.User, u.display or u.sam, u.sam, u.email, u.dn, us.is_enabled(u.uac))
                elif id_ in computers:
                    c = computers[id_]
                    m = GroupMember(c.id, MemberKind.Computer, c.name, c.name + "$", None, c.dn, not c.disabled)
                elif id_ in groups:
                    g = groups[id_]
                    m = GroupMember(g.id, MemberKind.Group, g.name, g.name, None, g.dn, None)
                else:
                    continue
                if s.kind is not None and m.kind != s.kind:
                    continue
                if t and not (_has(m.name, t) or _has(m.sam_account_name, t) or _has(m.email, t)):
                    continue
                matches.append(m)
            matches.sort(key=lambda m: m.name.upper())
            size = min(max(s.page_size, 1), 1000)
            page = max(1, s.page)
            return PagedResult(matches[(page - 1) * size:(page - 1) * size + size], len(matches), page, size)

    def _ou(self, dn: str) -> DirectoryOu:
        return DirectoryOu(dn, _ou_name(dn), any(dn_equal(parent_dn(x), dn) for x in fd.OU_LIST))

    def browse_ous(self, parent: str | None) -> list[DirectoryOu]:
        self._guard()
        parent = fd.BASE if not parent or not parent.strip() else parent
        found = [o for o in fd.OU_LIST if dn_equal(parent_dn(o), parent)]
        found.sort(key=lambda o: _ou_name(o).upper())
        return [self._ou(o) for o in found]

    def search_ous(self, text: str, limit: int) -> list[DirectoryOu]:
        self._guard()
        return [self._ou(o) for o in fd.OU_LIST if _has(_ou_name(o), text)][:limit]

    def get_ou(self, dn: str) -> DirectoryOu | None:
        self._guard()
        ou = next((o for o in fd.OU_LIST if dn_equal(o, dn)), None)
        return self._ou(ou) if ou else None

    def lockout_times(self, since_utc: datetime, max_items: int) -> list[datetime]:
        self._guard()
        with self._lock:
            return [u.locked_at for u in self._d.users if u.locked_out and u.locked_at is not None and u.locked_at >= since_utc][:max_items]

    def count_users(self, flt: UserFilter) -> int:
        return self.search_users(UserSearch(None, flt, 1, 1, None, sys.maxsize, ReadOptions())).total

    def count_computers(self, flt: ComputerFilter) -> int:
        return self.search_computers(ComputerSearch(None, flt, 1, 1, None, sys.maxsize, ReadOptions())).total

    # ------------------------------------------------------------------ writes (all support dry-run)

    def _preflight(self, id_: uuid.UUID, kind: ObjectKind, dry_run: bool) -> tuple[DirectoryResult | None, list[DryRunCheck]]:
        checks: list[DryRunCheck] = []
        if kind == ObjectKind.User:
            exists = any(u.id == id_ for u in self._d.users)
        elif kind == ObjectKind.Computer:
            exists = any(c.id == id_ for c in self._d.computers)
        else:
            exists = any(g.id == id_ for g in self._d.groups)
        if not exists:
            checks.append(DryRunCheck("Target object found by objectGUID", False, "No object with that objectGUID"))
            return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The object no longer exists in the directory.", checks), checks
        checks.append(DryRunCheck("Target object found by objectGUID", True))
        allowed = id_ not in self._d.denied_targets
        checks.append(DryRunCheck("Service account has the rights to make this change (allowedAttributesEffective)", allowed,
                                  None if allowed else "The service account has no write access to this object"))
        if allowed:
            return None, checks
        return DirectoryResult.fail(dry_run, DirectoryErrors.PERMISSION_DENIED, "The service account does not have permission to change this object.", checks), checks

    def _user(self, id_: uuid.UUID) -> fd.FakeUser:
        return next(x for x in self._d.users if x.id == id_)

    def _computer(self, id_: uuid.UUID) -> fd.FakeComputer:
        return next(x for x in self._d.computers if x.id == id_)

    def reset_password(self, user_id: uuid.UUID, new_password: str, options: ResetPasswordOptions, dry_run: bool) -> DirectoryResult:
        self._guard()
        with self._lock:
            failed, checks = self._preflight(user_id, ObjectKind.User, dry_run)
            if failed:
                return failed
            u = self._user(user_id)
            changes = [DirectoryChange("Password", None, "Reset (value not shown)")]
            if options.must_change_at_next_sign_in:
                changes.append(DirectoryChange("Must change password at next sign-in", "Yes" if u.pwd_last_set == 0 else "No", "Yes"))
            if options.unlock_account:
                changes.append(DirectoryChange("Locked out", "Yes" if u.locked_out else "No", "No"))
            # A dry run never looks at, or sends, the password.
            if dry_run:
                return DirectoryResult.ok(True, changes, checks)
            problem = _check_password_policy(new_password, u.sam)
            if problem:
                return DirectoryResult.fail(False, DirectoryErrors.PASSWORD_REJECTED, problem)
            u.pwd_last_set = 0 if options.must_change_at_next_sign_in else us.to_filetime(utcnow())
            if options.unlock_account:
                u.locked_out = False
                u.locked_at = None
            u.changed = utcnow()
            return DirectoryResult.ok(False, changes)

    def unlock(self, user_id: uuid.UUID, dry_run: bool) -> DirectoryResult:
        self._guard()
        with self._lock:
            failed, checks = self._preflight(user_id, ObjectKind.User, dry_run)
            if failed:
                return failed
            u = self._user(user_id)
            changes = [DirectoryChange("Locked out", "Yes" if u.locked_out else "No", "No")]
            if not dry_run:
                u.locked_out = False
                u.locked_at = None
                u.changed = utcnow()
            return DirectoryResult.ok(dry_run, changes, checks)

    def set_enabled(self, object_id: uuid.UUID, kind: ObjectKind, enabled: bool, dry_run: bool) -> DirectoryResult:
        self._guard()
        with self._lock:
            if kind == ObjectKind.Group:
                return DirectoryResult.fail(dry_run, DirectoryErrors.CONSTRAINT, "Groups cannot be enabled or disabled.")
            failed, checks = self._preflight(object_id, kind, dry_run)
            if failed:
                return failed
            was = us.is_enabled(self._user(object_id).uac) if kind == ObjectKind.User else not self._computer(object_id).disabled
            changes = [DirectoryChange("Enabled", "Yes" if was else "No", "Yes" if enabled else "No")]
            if not dry_run:
                if kind == ObjectKind.User:
                    u = self._user(object_id)
                    u.uac = u.uac & ~us.ACCOUNT_DISABLE if enabled else u.uac | us.ACCOUNT_DISABLE
                    u.changed = utcnow()
                else:
                    c = self._computer(object_id)
                    c.disabled = not enabled
                    c.changed = utcnow()
            return DirectoryResult.ok(dry_run, changes, checks)

    def move(self, object_id: uuid.UUID, kind: ObjectKind, target_ou_dn: str, dry_run: bool) -> DirectoryResult:
        self._guard()
        with self._lock:
            if kind == ObjectKind.Group:
                return DirectoryResult.fail(dry_run, DirectoryErrors.CONSTRAINT, "Groups cannot be moved in Version 1.")
            failed, checks = self._preflight(object_id, kind, dry_run)
            if failed:
                return failed
            target = next((o for o in fd.OU_LIST if dn_equal(o, target_ou_dn)), None)
            checks.append(DryRunCheck("Target OU exists", target is not None, None if target else "The target OU was not found"))
            if target is None:
                return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The target OU does not exist.", checks)
            checks.append(DryRunCheck("Service account may create this object type in the target OU (allowedChildClassesEffective)", True))
            from_ = self._user(object_id).ou if kind == ObjectKind.User else self._computer(object_id).ou
            changes = [DirectoryChange("OU", from_, target)]
            if not dry_run:
                obj = self._user(object_id) if kind == ObjectKind.User else self._computer(object_id)
                obj.ou = target
                obj.changed = utcnow()
            return DirectoryResult.ok(dry_run, changes, checks)

    def _change_membership(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], add: bool, dry_run: bool) -> DirectoryResult:
        self._guard()
        with self._lock:
            kind = ObjectKind.User if any(u.id == member_id for u in self._d.users) else ObjectKind.Computer
            failed, checks = self._preflight(member_id, kind, dry_run)
            if failed:
                return failed
            changes: list[DirectoryChange] = []
            for gid in group_ids:
                g = next((x for x in self._d.groups if x.id == gid), None)
                if g is None:
                    checks.append(DryRunCheck("Group found by objectGUID", False))
                    return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The group no longer exists.", checks)
                checks.append(DryRunCheck(f"Group '{g.name}' found", True))
                is_member = member_id in self._d.members.get(gid, ())
                if add and is_member:
                    return DirectoryResult.fail(dry_run, DirectoryErrors.ALREADY_MEMBER, f"Already a member of {g.name}.", checks)
                if not add and not is_member:
                    return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_MEMBER, f"Not a direct member of {g.name}.", checks)
                if gid in self._d.denied_targets:
                    return DirectoryResult.fail(dry_run, DirectoryErrors.PERMISSION_DENIED, "The service account cannot change this group.", checks)
                checks.append(DryRunCheck(f"Service account may modify 'member' on '{g.name}' (allowedAttributesEffective)", True))
                changes.append(DirectoryChange("Group membership: " + g.name, "Member" if is_member else "Not a member", "Member" if add else "Not a member"))
            if not dry_run:
                for gid in group_ids:
                    s = self._d.members.setdefault(gid, set())
                    if add:
                        s.add(member_id)
                    else:
                        s.discard(member_id)
            return DirectoryResult.ok(dry_run, changes, checks)

    def add_to_groups(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], dry_run: bool) -> DirectoryResult:
        return self._change_membership(member_id, group_ids, True, dry_run)

    def remove_from_groups(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], dry_run: bool) -> DirectoryResult:
        return self._change_membership(member_id, group_ids, False, dry_run)

    def test_connection(self) -> ConnectionTestResult:
        self._guard()
        return ConnectionTestResult(True, [
            ConnectionStep("Bind", True, "Fake in-memory directory (no network)"),
            ConnectionStep("Search base", True, fd.BASE),
            ConnectionStep("Secure connection", True, "Not applicable to the Fake provider"),
            ConnectionStep("Sample search", True, f"{len(self._d.users)} users, {len(self._d.computers)} computers, {len(self._d.groups)} groups"),
        ])


def _check_password_policy(pw: str, sam: str) -> str | None:
    """A stand-in for the domain policy: 8+ characters, three of four character classes, not the account name."""
    classes = (any(c.islower() for c in pw) + any(c.isupper() for c in pw) + any(c.isdigit() for c in pw)
               + any(not c.isalnum() for c in pw))
    if len(pw) < 8 or classes < 3 or sam.lower() in pw.lower():
        return "The password does not meet the domain password policy (length, complexity or history)."
    return None
