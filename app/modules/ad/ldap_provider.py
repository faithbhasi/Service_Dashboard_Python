"""Active Directory over LDAPS using ldap3.

Binds as the process identity (Kerberos/GSSAPI, for example a gMSA) so no password is stored; LDAP bind credentials in the
configuration are for local testing only and the application refuses to start with them outside Development.
One short-lived connection per operation keeps it simple and thread-safe. Every write supports a dry run that only reads
(including allowedAttributesEffective / allowedChildClassesEffective).
"""
from __future__ import annotations

import re
import ssl
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import TypeVar

from ldap3 import BASE, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, NONE, NTLM, SASL, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import (
    LDAPAttributeOrValueExistsResult, LDAPConstraintViolationResult, LDAPEntryAlreadyExistsResult, LDAPException,
    LDAPInsufficientAccessRightsResult, LDAPNoSuchAttributeResult, LDAPNoSuchObjectResult, LDAPOperationResult, LDAPUnwillingToPerformResult,
)

from ...config import ActiveDirectoryOptions
from ...logging_setup import get_logger
from . import ldap_text as lt
from . import user_status as us
from .dn import is_valid_dn, parent_dn, split_rdns
from .provider import (
    ComputerFilter, ComputerSearch, ConnectionStep, ConnectionTestResult, DirectoryChange, DirectoryComputer, DirectoryErrors, DirectoryGroup,
    DirectoryOu, DirectoryResult, DirectoryUnavailableError, DirectoryUser, DryRunCheck, GroupMember, GroupSearch, MemberKind, MemberSearch,
    Memberships, NestedMembership, ObjectKind, ObjectRef, PagedResult, ReadOptions, ResetPasswordOptions, SuggestedAllowlists, UserFilter,
    UserSearch,
)

log = get_logger("ldap")
T = TypeVar("T")
PAGE = 500
MAX_SCAN = 100_000  # an upper bound for listings that have no configured limit (group members)


class Entry:
    """One directory entry with its raw (bytes) attribute values, looked up case-insensitively."""

    def __init__(self, dn: str, raw: dict):
        self.dn = dn
        self._raw = {k.lower(): v for k, v in raw.items()}

    def has(self, attr: str) -> bool:
        return bool(self._raw.get(attr.lower()))

    def values(self, attr: str) -> list[str]:
        return [v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v) for v in self._raw.get(attr.lower(), [])]

    def s(self, attr: str) -> str | None:
        v = self.values(attr)
        return v[0] if v else None

    def l(self, attr: str) -> int:  # noqa: E743 (a one-letter name keeps the mappers short)
        try:
            return int(self.s(attr) or 0)
        except ValueError:
            return 0

    def i(self, attr: str) -> int:
        return max(-(2**31), min(self.l(attr), 2**31 - 1))

    def guid(self) -> uuid.UUID:
        v = self._raw.get("objectguid")
        return uuid.UUID(bytes_le=bytes(v[0])) if v and isinstance(v[0], (bytes, bytearray)) and len(v[0]) == 16 else uuid.UUID(int=0)

    def raw_bytes(self, attr: str) -> bytes | None:
        v = self._raw.get(attr.lower())
        return bytes(v[0]) if v and isinstance(v[0], (bytes, bytearray)) else None

    def generalized_time(self, attr: str) -> datetime | None:
        m = re.match(r"^(\d{14})(?:\.\d+)?Z$", self.s(attr) or "")
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC) if m else None

    def file_time(self, attr: str) -> datetime | None:
        return us.from_filetime(self.l(attr))

    @property
    def ou(self) -> str:
        return parent_dn(self.dn)


def _entries(response) -> Iterator[Entry]:
    for item in response or []:
        if item.get("type") == "searchResEntry":
            yield Entry(item["dn"], item.get("raw_attributes", {}))


def _user_attrs(o: ReadOptions) -> list[str]:
    return [
        "objectGUID", "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail",
        o.employee_id_attribute if lt.is_safe_attribute_name(o.employee_id_attribute) else "employeeID",
        "title", "department", "physicalDeliveryOfficeName", "telephoneNumber", "mobile", "description", "manager",
        "userAccountControl", "msDS-User-Account-Control-Computed", "accountExpires", "pwdLastSet",
        "msDS-UserPasswordExpiryTimeComputed", "msDS-ResultantPSO", "lastLogonTimestamp", "whenCreated", "whenChanged",
        "primaryGroupID", "adminCount",
    ]


def _computer_attrs(o: ReadOptions) -> list[str]:
    attrs = ["objectGUID", "cn", "dNSHostName", "userAccountControl", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp",
             "pwdLastSet", "managedBy", "description", "whenChanged", "whenCreated", "adminCount"]
    last = o.computer_last_user_attribute
    if lt.is_safe_attribute_name(last) and last.lower() not in (a.lower() for a in attrs):
        attrs.append(last)
    return attrs


GROUP_ATTRS = ["objectGUID", "cn", "description", "groupType", "managedBy", "adminCount", "distinguishedName", "objectClass"]
RIGHTS_ATTRS = ["distinguishedName", "objectGUID", "userAccountControl", "allowedAttributesEffective", "cn"]


def _map_group(e: Entry, member_count: int | None = None) -> DirectoryGroup:
    gt = e.i("groupType")
    scope = "Global" if gt & 0x2 else "DomainLocal" if gt & 0x4 else "Universal" if gt & 0x8 else "Global"
    return DirectoryGroup(
        id=e.guid(), dn=e.dn, ou=e.ou, name=e.s("cn") or "", description=e.s("description"), scope=scope,
        type="Security" if gt & -(2**31) else "Distribution", admin_count=e.l("adminCount") > 0, member_count=member_count)


def _kind_of(classes: list[str]) -> ObjectKind:
    lower = {c.lower() for c in classes}
    return ObjectKind.Computer if "computer" in lower else ObjectKind.Group if "group" in lower else ObjectKind.User


class LdapDirectoryProvider:
    provider_name = "Ldap"
    suggested_defaults: SuggestedAllowlists | None = None  # a real directory starts with nothing manageable

    def __init__(self, options: ActiveDirectoryOptions):
        self._o = options

    @property
    def base_dn(self) -> str:
        return self._o.base_dn

    # ------------------------------------------------------------------ plumbing

    def _connect(self) -> Connection:
        o = self._o
        # Certificate checks stay on. The switch exists only for local troubleshooting and the app refuses to start with it off in Production.
        tls = Tls(validate=ssl.CERT_REQUIRED if o.verify_certificate else ssl.CERT_NONE) if o.use_ldaps else None
        server = Server(o.server, port=o.port, use_ssl=o.use_ldaps, tls=tls, get_info=NONE, connect_timeout=30)
        kwargs: dict = {"raise_exceptions": True, "receive_timeout": 30, "auto_referrals": False, "read_only": False}
        if o.bind_username:
            # Local testing only (the startup checks refuse this outside Development). A simple bind is only used over LDAPS.
            c = Connection(server, user=o.bind_username, password=o.bind_password, authentication=SIMPLE if o.use_ldaps else NTLM, **kwargs)
        else:
            # Integrated: the identity of the process (Kerberos). Needs the optional 'gssapi' (Linux) or 'winkerberos' (Windows) package.
            c = Connection(server, authentication=SASL, sasl_mechanism="GSSAPI", **kwargs)
        c.bind()
        return c

    def _run(self, work: Callable[[Connection], T]) -> T:
        try:
            c = self._connect()
        except LDAPException as ex:
            raise DirectoryUnavailableError(f"LDAP connect or bind failed: {type(ex).__name__}", ex) from ex
        except OSError as ex:
            raise DirectoryUnavailableError(f"LDAP connection failed: {type(ex).__name__}", ex) from ex
        try:
            return work(c)
        except LDAPOperationResult as ex:
            log.error("LDAP operation failed with %s", ex.result)
            raise DirectoryUnavailableError(f"LDAP error {ex.result}", ex) from ex
        except LDAPException as ex:
            raise DirectoryUnavailableError(f"LDAP error: {type(ex).__name__}", ex) from ex
        finally:
            try:
                c.unbind()
            except Exception:  # noqa: BLE001 - closing must never hide the real outcome
                pass

    # ------------------------------------------------------------------ low-level search

    @staticmethod
    def _scan(c: Connection, base: str, flt: str, attrs: list[str], scope=SUBTREE, max_items: int = MAX_SCAN,
              post: Callable[[Entry], bool] | None = None) -> list[Entry]:
        """Paged-results scan (page size 500) that stops after max_items matches. A missing base object gives an empty list."""
        found: list[Entry] = []
        try:
            for e in _entries(c.extend.standard.paged_search(base, flt, search_scope=scope, attributes=attrs, paged_size=PAGE, generator=True)):
                if post is not None and not post(e):
                    continue
                found.append(e)
                if len(found) >= max_items:
                    break
        except LDAPNoSuchObjectResult:
            return []
        return found

    def _read_one(self, c: Connection, base: str, flt: str, attrs: list[str], scope=SUBTREE) -> Entry | None:
        found = self._scan(c, base, flt, attrs, scope, max_items=1)
        return found[0] if found else None

    def _read_by_guid(self, c: Connection, id_: uuid.UUID, attrs: list[str], category: str | None = None) -> Entry | None:
        flt = lt.by_guid(id_) if category is None else f"(&{lt.by_guid(id_)}{category})"
        return self._read_one(c, self.base_dn, flt, attrs)

    def _read_by_dn(self, c: Connection, dn: str, attrs: list[str]) -> Entry | None:
        return self._read_one(c, dn, "(objectClass=*)", attrs, BASE) if is_valid_dn(dn) else None

    def _resolve_cn(self, c: Connection, dn: str) -> str | None:
        e = self._read_by_dn(c, dn, ["cn"])
        return e.s("cn") if e else None

    def _resolve_ref(self, c: Connection, dn: str) -> ObjectRef | None:
        e = self._read_by_dn(c, dn, ["objectGUID", "displayName", "cn", "objectClass", "objectCategory"])
        if e is None:
            return None
        return ObjectRef(e.guid(), e.s("displayName") or e.s("cn") or dn, _kind_of(e.values("objectClass")))

    def _search_page(self, c: Connection, base: str, flt: str, attrs: list[str], page: int, page_size: int, limit: int,
                     post: Callable[[Entry], bool] | None = None) -> tuple[list[Entry], int, bool]:
        """Scans (server-side filtered) up to the limit, orders by cn, and slices the page. ldap3 has no virtual list view, so
        the directory is asked for at most limit+1 matches."""
        page_size = max(1, min(page_size, 1000))
        page = max(1, page)
        scan_cap = min(limit, MAX_SCAN)
        everything = self._scan(c, base, flt, attrs, max_items=scan_cap + 1, post=post)
        capped = len(everything) > scan_cap
        ordered = sorted(everything[:scan_cap], key=lambda e: (e.s("cn") or e.dn).upper())
        start = (page - 1) * page_size
        return ordered[start:start + page_size], len(ordered), capped

    def _count(self, c: Connection, base: str, flt: str, attrs: list[str], post: Callable[[Entry], bool] | None = None) -> int:
        n = 0
        for e in _entries(c.extend.standard.paged_search(base, flt, search_scope=SUBTREE, attributes=attrs, paged_size=1000, generator=True)):
            if post is None or post(e):
                n += 1
        return n

    def _search_root(self, ou_dn: str | None) -> str:
        return ou_dn if ou_dn and is_valid_dn(ou_dn) else self.base_dn

    # ------------------------------------------------------------------ mapping

    def _map_user(self, c: Connection, e: Entry, o: ReadOptions, resolve_manager: bool) -> DirectoryUser:
        now = datetime.now(UTC)
        uac = e.i("userAccountControl")
        computed = e.i("msDS-User-Account-Control-Computed")
        pwd_set = e.l("pwdLastSet")
        expiry = e.l("msDS-UserPasswordExpiryTimeComputed") if e.has("msDS-UserPasswordExpiryTimeComputed") else None
        ae_kind, ae_date = us.account_expiry(e.l("accountExpires"), now)
        pw_status, pw_date = us.password(uac, computed, pwd_set, expiry, now)
        emp = o.employee_id_attribute if lt.is_safe_attribute_name(o.employee_id_attribute) else "employeeID"
        pso = e.s("msDS-ResultantPSO")
        mgr = e.s("manager")
        locked = us.is_locked_out(computed)
        flags_uac = uac | (us.LOCKOUT if locked else 0)
        return DirectoryUser(
            id=e.guid(), dn=e.dn, ou=e.ou, sam_account_name=e.s("sAMAccountName") or "", user_principal_name=e.s("userPrincipalName"),
            display_name=e.s("displayName"), given_name=e.s("givenName"), surname=e.s("sn"), email=e.s("mail"), employee_id=e.s(emp),
            title=e.s("title"), department=e.s("department"), office=e.s("physicalDeliveryOfficeName"), phone=e.s("telephoneNumber"),
            mobile=e.s("mobile"), description=e.s("description"),
            manager=self._resolve_ref(c, mgr) if resolve_manager and mgr else None,
            enabled=us.is_enabled(uac), locked_out=locked, account_expiry=ae_kind, account_expires_utc=ae_date,
            password_status=pw_status, password_expires_utc=pw_date, password_last_set_utc=e.file_time("pwdLastSet"),
            last_logon_utc=e.file_time("lastLogonTimestamp"), created_utc=e.generalized_time("whenCreated"), changed_utc=e.generalized_time("whenChanged"),
            resultant_pso=self._resolve_cn(c, pso) if pso else None, user_account_control=flags_uac,
            uac_flags=us.describe_flags(flags_uac | (computed & us.COMPUTED_PASSWORD_EXPIRED)),
            primary_group_id=e.i("primaryGroupID"), admin_count=e.l("adminCount") > 0)

    def _map_computer(self, c: Connection, e: Entry, o: ReadOptions, resolve_managed_by: bool) -> DirectoryComputer:
        mb = e.s("managedBy")
        last = o.computer_last_user_attribute
        return DirectoryComputer(
            id=e.guid(), dn=e.dn, ou=e.ou, name=e.s("cn") or "", dns_host_name=e.s("dNSHostName"), enabled=us.is_enabled(e.i("userAccountControl")),
            operating_system=e.s("operatingSystem"), os_version=e.s("operatingSystemVersion"), last_logon_utc=e.file_time("lastLogonTimestamp"),
            password_last_set_utc=e.file_time("pwdLastSet"), managed_by=self._resolve_ref(c, mb) if resolve_managed_by and mb else None,
            description=e.s("description"), changed_utc=e.generalized_time("whenChanged"), created_utc=e.generalized_time("whenCreated"),
            last_logged_in_user=e.s(last) if lt.is_safe_attribute_name(last) else None, admin_count=e.l("adminCount") > 0)

    # ------------------------------------------------------------------ reads

    def search_users(self, s: UserSearch) -> PagedResult[DirectoryUser]:
        def work(c: Connection):
            flt = lt.users_filter(s.text, s.filter, s.options.employee_id_attribute, datetime.now(UTC), s.department, s.title)
            # A lockoutTime alone does not prove the account is still locked, so confirm with the computed bit.
            post = (lambda e: us.is_locked_out(e.i("msDS-User-Account-Control-Computed"))) if s.filter == UserFilter.Locked else None
            items, total, capped = self._search_page(c, self._search_root(s.ou_dn), flt, _user_attrs(s.options), s.page, s.page_size, s.limit, post)
            return PagedResult([self._map_user(c, e, s.options, False) for e in items], total, s.page, s.page_size, capped)

        return self._run(work)

    def get_user(self, id: uuid.UUID, options: ReadOptions) -> DirectoryUser | None:
        def work(c: Connection):
            e = self._read_by_guid(c, id, _user_attrs(options), lt.USER_BASE)
            return self._map_user(c, e, options, True) if e else None

        return self._run(work)

    def search_computers(self, s: ComputerSearch) -> PagedResult[DirectoryComputer]:
        def work(c: Connection):
            items, total, capped = self._search_page(c, self._search_root(s.ou_dn), lt.computers_filter(s.text, s.filter, s.os_type),
                                                     _computer_attrs(s.options), s.page, s.page_size, s.limit)
            return PagedResult([self._map_computer(c, e, s.options, False) for e in items], total, s.page, s.page_size, capped)

        return self._run(work)

    def get_computer(self, id: uuid.UUID, options: ReadOptions) -> DirectoryComputer | None:
        def work(c: Connection):
            e = self._read_by_guid(c, id, _computer_attrs(options), lt.COMPUTER_BASE)
            return self._map_computer(c, e, options, True) if e else None

        return self._run(work)

    def search_groups(self, s: GroupSearch) -> PagedResult[DirectoryGroup]:
        def work(c: Connection):
            items, total, capped = self._search_page(c, self.base_dn, lt.groups_filter(s.text), GROUP_ATTRS, s.page, s.page_size, s.limit)
            return PagedResult([_map_group(e) for e in items], total, s.page, s.page_size, capped)

        return self._run(work)

    def get_group(self, id: uuid.UUID) -> DirectoryGroup | None:
        def work(c: Connection):
            e = self._read_by_guid(c, id, GROUP_ATTRS, lt.GROUP_BASE)
            if e is None:
                return None
            count = self._count(c, self.base_dn, lt.members_filter(e.dn, None, None), ["cn"])
            g = _map_group(e, count)
            mb = e.s("managedBy")
            if mb:
                g.managed_by = self._resolve_ref(c, mb)
            return g

        return self._run(work)

    def get_group_by_dn(self, dn: str) -> DirectoryGroup | None:
        def work(c: Connection):
            e = self._read_by_dn(c, dn, GROUP_ATTRS)
            return _map_group(e) if e and "group" in (v.lower() for v in e.values("objectClass")) else None

        return self._run(work)

    def get_memberships(self, object_id: uuid.UUID, kind: ObjectKind) -> Memberships | None:
        def work(c: Connection):
            target = self._read_by_guid(c, object_id, ["distinguishedName", "memberOf", "primaryGroupID"])
            if target is None:
                return None
            direct_entries = [self._read_by_dn(c, dn, GROUP_ATTRS) for dn in target.values("memberOf")]
            direct = sorted((_map_group(e) for e in direct_entries if e is not None), key=lambda g: g.name.lower())
            direct_dns = {g.dn.lower() for g in direct}
            # Nested: every group reached through the chain; "via" is the first direct group that leads to it.
            nested: dict[str, NestedMembership] = {}
            for d in direct[:50]:
                for e in self._scan(c, self.base_dn, lt.nested_groups_of(d.dn), GROUP_ATTRS):
                    if e.dn.lower() not in direct_dns and e.dn.lower() not in nested:
                        nested[e.dn.lower()] = NestedMembership(_map_group(e), d.name)
            return Memberships(direct, sorted(nested.values(), key=lambda n: n.group.name.lower()), self._primary_group(c, target.i("primaryGroupID")))

        return self._run(work)

    def _primary_group(self, c: Connection, rid: int) -> DirectoryGroup | None:
        if rid <= 0:
            return None
        root = self._read_one(c, self.base_dn, "(objectClass=domain)", ["objectSid"], BASE)
        sid = root.raw_bytes("objectSid") if root else None
        if not sid:
            return None
        e = self._read_one(c, self.base_dn, f"(&{lt.GROUP_BASE}(objectSid={lt.escape_bytes(lt.append_rid(sid, rid))}))", GROUP_ATTRS)
        return _map_group(e) if e else None

    def search_group_members(self, group_id: uuid.UUID, s: MemberSearch) -> PagedResult[GroupMember]:
        def work(c: Connection):
            group = self._read_by_guid(c, group_id, ["distinguishedName"])
            if group is None:
                return PagedResult(page_size=s.page_size)
            attrs = ["objectGUID", "cn", "sAMAccountName", "mail", "displayName", "objectClass", "userAccountControl"]
            items, total, _ = self._search_page(c, self.base_dn, lt.members_filter(group.dn, s.text, s.kind), attrs, s.page, s.page_size, MAX_SCAN)
            out = []
            for e in items:
                kind = _kind_of(e.values("objectClass"))
                out.append(GroupMember(e.guid(), kind, e.s("displayName") or e.s("cn") or "", e.s("sAMAccountName"), e.s("mail"), e.dn,
                                       None if kind == MemberKind.Group else us.is_enabled(e.i("userAccountControl"))))
            return PagedResult(out, total, s.page, s.page_size)

        return self._run(work)

    def browse_ous(self, parent: str | None) -> list[DirectoryOu]:
        def work(c: Connection):
            p = self.base_dn if not parent or not parent.strip() else parent
            if not is_valid_dn(p):
                return []
            found = self._scan(c, p, "(objectClass=organizationalUnit)", ["ou", "distinguishedName"], LEVEL)
            # has_children is assumed true: finding out would cost one extra query per OU. An empty expansion is harmless.
            return [DirectoryOu(e.dn, e.s("ou") or e.dn, True) for e in sorted(found, key=lambda e: (e.s("ou") or "").upper())]

        return self._run(work)

    def search_ous(self, text: str, limit: int) -> list[DirectoryOu]:
        def work(c: Connection):
            found = self._scan(c, self.base_dn, f"(&(objectClass=organizationalUnit)(ou=*{lt.escape_filter_value(text)}*))", ["ou", "distinguishedName"],
                               max_items=limit)
            return [DirectoryOu(e.dn, e.s("ou") or "", True) for e in found]

        return self._run(work)

    def get_ou(self, dn: str) -> DirectoryOu | None:
        def work(c: Connection):
            e = self._read_by_dn(c, dn, ["ou", "objectClass"])
            return DirectoryOu(e.dn, e.s("ou") or "", True) if e and "organizationalunit" in (v.lower() for v in e.values("objectClass")) else None

        return self._run(work)

    def lockout_times(self, since_utc: datetime, max_items: int) -> list[datetime]:
        def work(c: Connection):
            # lockoutTime is a FILETIME; 0 means "not locked". Only the time is read, nothing else about the account.
            flt = f"(&{lt.USER_BASE}(lockoutTime>={us.to_filetime(since_utc)}))"
            entries = self._scan(c, self.base_dn, flt, ["lockoutTime"], max_items=max(1, min(max_items, 5000)))
            return [t for t in (us.from_filetime(e.l("lockoutTime")) for e in entries) if t is not None]

        return self._run(work)

    def count_users(self, flt: UserFilter) -> int:
        def work(c: Connection):
            post = (lambda e: us.is_locked_out(e.i("msDS-User-Account-Control-Computed"))) if flt == UserFilter.Locked else None
            return self._count(c, self.base_dn, lt.users_filter(None, flt, "employeeID", datetime.now(UTC)), ["msDS-User-Account-Control-Computed"], post)

        return self._run(work)

    def count_computers(self, flt: ComputerFilter) -> int:
        return self._run(lambda c: self._count(c, self.base_dn, lt.computers_filter(None, flt), ["cn"]))

    # ------------------------------------------------------------------ writes

    @staticmethod
    def _can_write(e: Entry, attribute: str) -> bool:
        return attribute.lower() in (v.lower() for v in e.values("allowedAttributesEffective"))

    def _preflight(self, c: Connection, id_: uuid.UUID, dry_run: bool, attribute: str) -> tuple[DirectoryResult | None, Entry | None, list[DryRunCheck]]:
        """Common dry-run front half: find the target by objectGUID and check we may write the attribute."""
        checks: list[DryRunCheck] = []
        e = self._read_by_guid(c, id_, RIGHTS_ATTRS)
        if e is None:
            checks.append(DryRunCheck("Target object found by objectGUID", False, "No object with that objectGUID"))
            return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The object no longer exists in the directory.", checks), None, checks
        checks.append(DryRunCheck("Target object found by objectGUID", True))
        can = self._can_write(e, attribute)
        checks.append(DryRunCheck(f"Service account may write '{attribute}' on the target (allowedAttributesEffective)", can,
                                  None if can else "The service account has no write access to this attribute"))
        if can:
            return None, e, checks
        return DirectoryResult.fail(dry_run, DirectoryErrors.PERMISSION_DENIED, "The service account does not have permission to make this change.", checks), e, checks

    @staticmethod
    def _map_error(ex: LDAPOperationResult, password_change: bool = False) -> DirectoryResult:
        if isinstance(ex, LDAPInsufficientAccessRightsResult):
            return DirectoryResult.fail(False, DirectoryErrors.PERMISSION_DENIED, "The service account does not have permission to make this change.")
        if isinstance(ex, LDAPNoSuchObjectResult):
            return DirectoryResult.fail(False, DirectoryErrors.NOT_FOUND, "The object no longer exists in the directory.")
        if isinstance(ex, (LDAPEntryAlreadyExistsResult, LDAPAttributeOrValueExistsResult)):
            return DirectoryResult.fail(False, DirectoryErrors.ALREADY_MEMBER, "Already a member.")
        if isinstance(ex, LDAPNoSuchAttributeResult):
            return DirectoryResult.fail(False, DirectoryErrors.NOT_MEMBER, "Not a direct member.")
        if password_change and isinstance(ex, (LDAPConstraintViolationResult, LDAPUnwillingToPerformResult)):
            return DirectoryResult.fail(False, DirectoryErrors.PASSWORD_REJECTED, "The domain rejected the password (length, complexity, history or minimum age).")
        return DirectoryResult.fail(False, DirectoryErrors.CONSTRAINT, f"The directory refused the change ({ex.result}).")

    def reset_password(self, user_id: uuid.UUID, new_password: str, options: ResetPasswordOptions, dry_run: bool) -> DirectoryResult:
        def work(c: Connection):
            failed, e, checks = self._preflight(c, user_id, dry_run, "unicodePwd")
            if failed:
                return failed
            if options.unlock_account:
                can_unlock = self._can_write(e, "lockoutTime")
                checks.append(DryRunCheck("Service account may write 'lockoutTime' on the target (allowedAttributesEffective)", can_unlock,
                                          None if can_unlock else "The service account has no write access to this attribute"))
                if not can_unlock:
                    return DirectoryResult.fail(dry_run, DirectoryErrors.PERMISSION_DENIED, "The service account does not have permission to unlock this account.", checks)
            changes = [DirectoryChange("Password", None, "Reset (value not shown)")]
            if options.must_change_at_next_sign_in:
                changes.append(DirectoryChange("Must change password at next sign-in", None, "Yes"))
            if options.unlock_account:
                changes.append(DirectoryChange("Locked out", None, "No"))
            if dry_run:
                return DirectoryResult.ok(True, changes, checks)  # no password is ever sent in a dry run
            quoted = bytearray(('"' + new_password + '"').encode("utf-16-le"))
            try:
                mods = {"unicodePwd": [(MODIFY_REPLACE, [bytes(quoted)])]}
                if options.must_change_at_next_sign_in:
                    mods["pwdLastSet"] = [(MODIFY_REPLACE, ["0"])]
                if options.unlock_account:
                    mods["lockoutTime"] = [(MODIFY_REPLACE, ["0"])]
                c.modify(e.dn, mods)
                return DirectoryResult.ok(False, changes)
            except LDAPOperationResult as ex:
                return self._map_error(ex, password_change=True)
            finally:
                for i in range(len(quoted)):
                    quoted[i] = 0

        return self._run(work)

    def unlock(self, user_id: uuid.UUID, dry_run: bool) -> DirectoryResult:
        def work(c: Connection):
            failed, e, checks = self._preflight(c, user_id, dry_run, "lockoutTime")
            if failed:
                return failed
            changes = [DirectoryChange("Locked out", None, "No")]
            if dry_run:
                return DirectoryResult.ok(True, changes, checks)
            try:
                c.modify(e.dn, {"lockoutTime": [(MODIFY_REPLACE, ["0"])]})
                return DirectoryResult.ok(False, changes)
            except LDAPOperationResult as ex:
                return self._map_error(ex)

        return self._run(work)

    def set_enabled(self, object_id: uuid.UUID, kind: ObjectKind, enabled: bool, dry_run: bool) -> DirectoryResult:
        def work(c: Connection):
            if kind == ObjectKind.Group:
                return DirectoryResult.fail(dry_run, DirectoryErrors.CONSTRAINT, "Groups cannot be enabled or disabled.")
            failed, e, checks = self._preflight(c, object_id, dry_run, "userAccountControl")
            if failed:
                return failed
            uac = e.i("userAccountControl")
            was = us.is_enabled(uac)
            changes = [DirectoryChange("Enabled", "Yes" if was else "No", "Yes" if enabled else "No")]
            if dry_run or was == enabled:
                return DirectoryResult.ok(dry_run, changes, checks)
            nxt = uac & ~us.ACCOUNT_DISABLE if enabled else uac | us.ACCOUNT_DISABLE
            try:
                c.modify(e.dn, {"userAccountControl": [(MODIFY_REPLACE, [str(nxt)])]})
                return DirectoryResult.ok(False, changes)
            except LDAPOperationResult as ex:
                return self._map_error(ex)

        return self._run(work)

    def move(self, object_id: uuid.UUID, kind: ObjectKind, target_ou_dn: str, dry_run: bool) -> DirectoryResult:
        def work(c: Connection):
            if kind == ObjectKind.Group:
                return DirectoryResult.fail(dry_run, DirectoryErrors.CONSTRAINT, "Groups cannot be moved in Version 1.")
            entry = self._read_by_guid(c, object_id, ["distinguishedName", "objectGUID"])
            checks = [DryRunCheck("Target object found by objectGUID", entry is not None)]
            if entry is None:
                return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The object no longer exists in the directory.", checks)
            if not is_valid_dn(target_ou_dn):
                return DirectoryResult.fail(dry_run, DirectoryErrors.CONSTRAINT, "The target OU is not a valid distinguished name.", checks)
            target = self._read_one(c, target_ou_dn, "(objectClass=organizationalUnit)", ["distinguishedName", "allowedChildClassesEffective"], BASE)
            checks.append(DryRunCheck("Target OU exists", target is not None))
            if target is None:
                return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The target OU does not exist.", checks)
            cls = "user" if kind == ObjectKind.User else "computer"
            can_create = cls in (v.lower() for v in target.values("allowedChildClassesEffective"))
            checks.append(DryRunCheck(f"Service account may create '{cls}' objects in the target OU (allowedChildClassesEffective)", can_create))
            if not can_create:
                return DirectoryResult.fail(dry_run, DirectoryErrors.PERMISSION_DENIED, "The service account cannot create this object type in the target OU.", checks)
            changes = [DirectoryChange("OU", parent_dn(entry.dn), target.dn)]
            if dry_run:
                return DirectoryResult.ok(True, changes, checks)
            try:
                c.modify_dn(entry.dn, split_rdns(entry.dn)[0], new_superior=target.dn)
                return DirectoryResult.ok(False, changes)
            except LDAPOperationResult as ex:
                return self._map_error(ex)

        return self._run(work)

    def _change_membership(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], add: bool, dry_run: bool) -> DirectoryResult:
        def work(c: Connection):
            member = self._read_by_guid(c, member_id, ["distinguishedName", "memberOf"])
            checks = [DryRunCheck("Target object found by objectGUID", member is not None)]
            if member is None:
                return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The object no longer exists in the directory.", checks)
            member_of = {v.lower() for v in member.values("memberOf")}
            groups: list[Entry] = []
            changes: list[DirectoryChange] = []
            for gid in group_ids:
                g = self._read_by_guid(c, gid, ["distinguishedName", "cn", "allowedAttributesEffective"])
                if g is None:
                    checks.append(DryRunCheck("Group found by objectGUID", False))
                    return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_FOUND, "The group no longer exists.", checks)
                name = g.s("cn") or g.dn
                checks.append(DryRunCheck(f"Group '{name}' found", True))
                is_member = g.dn.lower() in member_of
                if add and is_member:
                    return DirectoryResult.fail(dry_run, DirectoryErrors.ALREADY_MEMBER, f"Already a member of {name}.", checks)
                if not add and not is_member:
                    return DirectoryResult.fail(dry_run, DirectoryErrors.NOT_MEMBER, f"Not a direct member of {name}.", checks)
                can = self._can_write(g, "member")
                checks.append(DryRunCheck(f"Service account may modify 'member' on '{name}' (allowedAttributesEffective)", can))
                if not can:
                    return DirectoryResult.fail(dry_run, DirectoryErrors.PERMISSION_DENIED, "The service account cannot change this group.", checks)
                groups.append(g)
                changes.append(DirectoryChange("Group membership: " + name, "Member" if is_member else "Not a member", "Member" if add else "Not a member"))
            if dry_run:
                return DirectoryResult.ok(True, changes, checks)
            try:
                for g in groups:
                    c.modify(g.dn, {"member": [(MODIFY_ADD if add else MODIFY_DELETE, [member.dn])]})
                return DirectoryResult.ok(False, changes)
            except LDAPOperationResult as ex:
                return self._map_error(ex)

        return self._run(work)

    def add_to_groups(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], dry_run: bool) -> DirectoryResult:
        return self._change_membership(member_id, group_ids, True, dry_run)

    def remove_from_groups(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], dry_run: bool) -> DirectoryResult:
        return self._change_membership(member_id, group_ids, False, dry_run)

    # ------------------------------------------------------------------ connection test

    def test_connection(self) -> ConnectionTestResult:
        o = self._o
        steps: list[ConnectionStep] = []
        try:
            c = self._connect()
        except (LDAPException, OSError) as ex:
            steps.append(ConnectionStep("Bind", False, f"LDAP error: {type(ex).__name__}"))
            return ConnectionTestResult(False, steps)
        try:
            who = "the application identity" if not o.bind_username else o.bind_username + " (local test credentials)"
            steps.append(ConnectionStep("Bind", True, f"Bound to {o.server}:{o.port} as {who}"))
            root = self._read_one(c, self.base_dn, "(objectClass=*)", ["distinguishedName"], BASE)
            steps.append(ConnectionStep("Search base", root is not None, f"Found {self.base_dn}" if root else f"{self.base_dn} was not found"))
            secure = o.use_ldaps and o.verify_certificate
            steps.append(ConnectionStep("Secure connection", secure, "LDAPS with certificate validation" if secure
                                        else "LDAPS with certificate validation is required (UseLdaps and VerifyCertificate must be true)"))
            sample = self._read_one(c, self.base_dn, lt.USER_BASE, ["sAMAccountName"])
            steps.append(ConnectionStep("Sample search", sample is not None, "A user search returned a result" if sample else "A user search returned nothing"))
        except LDAPException:
            steps.append(ConnectionStep("Search base", False, "The directory refused the request"))
        finally:
            try:
                c.unbind()
            except Exception:  # noqa: BLE001
                pass
        return ConnectionTestResult(bool(steps) and all(s.passed for s in steps), steps)
