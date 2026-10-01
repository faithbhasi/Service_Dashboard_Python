"""Active Directory module endpoints: /api/modules/ad/{users,computers,groups,ous,settings,activity}.

Every change goes through AdChangeService (permission, validation, re-read, allowlists, dry run, audit)."""
from __future__ import annotations

import enum
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from fastapi import APIRouter, Body, Depends
from sqlalchemy import select
from starlette.responses import StreamingResponse

from .. import csv_writer, permissions as P
from ..audit import AuditEntry
from ..audit_query import ObjectActivity
from ..db import AuditLog, AuditResult
from ..errors import ApiException, ModuleUnavailableError
from ..http_helpers import ok, problem
from ..modules.ad import services as svc
from ..modules.ad.dn import dn_equal, is_under_or_equal, is_valid_dn
from ..modules.ad.provider import ComputerFilter, DirectoryUnavailableError, MemberKind, ObjectKind, UserFilter
from ..modules.ad.settings import AdSettings
from ..util import utcnow
from ..web import Ctx, get_ctx, guard

MODULE = "ad"
router = APIRouter(prefix="/api/modules/ad")
E = TypeVar("E", bound=enum.Enum)


# ---------------------------------------------------------------------------------- binding helpers

def gid(value: str) -> uuid.UUID:
    """Route ids are GUIDs; anything else is simply not found, like a route constraint."""
    try:
        return uuid.UUID(value)
    except ValueError:
        raise ApiException(404, "Not Found", "Not found.", "not_found") from None


def enum_param(cls: type[E], value: str | None, default: E | None) -> E | None:
    if value is None or value == "":
        return default
    for m in cls:
        if m.name.lower() == value.strip().lower():
            return m
    raise ApiException(400, "Invalid request", f"'{value}' is not a valid value.", "validation")


def not_found(what: str):
    return problem(404, "Not found", f"{what} not found in the directory.")


def require_logs_access(ctx: Ctx, user) -> None:
    """A second policy on the same endpoint: both must pass (activity history needs the object's read right AND logs access)."""
    if not user.has_any(*P.LOGS_ACCESS):
        ctx.deny_audit()
        raise ApiException(403, "Access denied", "You do not have permission to do this.", "forbidden")


def change_response(r: svc.ChangeResult):
    return ok(r, status=r.http_status)


# ---------------------------------------------------------------------------------- users

@router.get("/users")
def users_search(q: str | None = None, filter: str | None = None, page: int = 1, pageSize: int = 25, ou: str | None = None,
                 department: str | None = None, title: str | None = None, ctx: Ctx = Depends(get_ctx),
                 _=Depends(guard(P.AD_USERS_READ, module=MODULE, rate="search"))):
    flt = enum_param(UserFilter, filter, UserFilter.All)
    return ok(svc.ad_services(ctx).directory.search_users(q, flt, page, pageSize, ou, department, title))


@router.get("/users/{id}")
def user_get(id: str, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_READ, module=MODULE))):
    u = svc.ad_services(ctx).directory.get_user(gid(id))
    return ok(u) if u else not_found("User")


@router.get("/users/{id}/groups")
def user_groups(id: str, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_READ, module=MODULE))):
    m = svc.ad_services(ctx).directory.get_memberships(gid(id), ObjectKind.User)
    return ok(m) if m else not_found("User")


@router.get("/users/{id}/activity")
def user_activity(id: str, page: int = 1, pageSize: int = 25, ctx: Ctx = Depends(get_ctx),
                  user=Depends(guard(P.AD_USERS_READ, module=MODULE))):
    """Everything done to this user through this application. Changes made with other tools are not shown."""
    require_logs_access(ctx, user)
    return ok(ObjectActivity(ctx.db, user).for_object(str(gid(id)), page, pageSize))


@router.post("/users/{id}/reset-password")
def user_reset_password(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                        _=Depends(guard(P.AD_USERS_RESET_PASSWORD, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.reset_password(gid(id), svc.ResetPasswordRequest.from_dict(body)))


@router.post("/users/{id}/unlock")
def user_unlock(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_UNLOCK, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.unlock(gid(id), svc.ChangeInput.from_dict(body)))


@router.post("/users/{id}/enable")
def user_enable(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_ENABLE, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.set_user_enabled(gid(id), True, svc.ChangeInput.from_dict(body)))


@router.post("/users/{id}/disable")
def user_disable(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_DISABLE, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.set_user_enabled(gid(id), False, svc.ChangeInput.from_dict(body)))


@router.post("/users/{id}/move")
def user_move(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_MOVE, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.move(gid(id), ObjectKind.User, svc.MoveRequest.from_dict(body)))


@router.get("/users/{id}/addable-groups")
def user_addable_groups(id: str, q: str | None = None, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_GROUPS_ADD, module=MODULE))):
    return ok(svc.ad_services(ctx).changes.addable_groups(gid(id), q))


@router.post("/users/{id}/groups/add")
def user_groups_add(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                    _=Depends(guard(P.AD_USERS_GROUPS_ADD, module=MODULE, rate="write"))):
    return ok({"results": svc.ad_services(ctx).changes.change_groups(gid(id), True, svc.GroupsRequest.from_dict(body))})


@router.post("/users/{id}/groups/remove")
def user_groups_remove(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                       _=Depends(guard(P.AD_USERS_GROUPS_REMOVE, module=MODULE, rate="write"))):
    return ok({"results": svc.ad_services(ctx).changes.change_groups(gid(id), False, svc.GroupsRequest.from_dict(body))})


# ---------------------------------------------------------------------------------- computers

@router.get("/computers")
def computers_search(q: str | None = None, filter: str | None = None, page: int = 1, pageSize: int = 25, ou: str | None = None,
                     os: str | None = None, ctx: Ctx = Depends(get_ctx),
                     _=Depends(guard(P.AD_COMPUTERS_READ, module=MODULE, rate="search"))):
    flt = enum_param(ComputerFilter, filter, ComputerFilter.All)
    return ok(svc.ad_services(ctx).directory.search_computers(q, flt, page, pageSize, ou, os))


@router.get("/computers/{id}")
def computer_get(id: str, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_COMPUTERS_READ, module=MODULE))):
    c = svc.ad_services(ctx).directory.get_computer(gid(id))
    return ok(c) if c else problem(404, "Not found", "Computer not found in the directory.")


@router.get("/computers/{id}/groups")
def computer_groups(id: str, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_COMPUTERS_READ, module=MODULE))):
    m = svc.ad_services(ctx).directory.get_memberships(gid(id), ObjectKind.Computer)
    return ok(m) if m else problem(404, "Not found", "Computer not found in the directory.")


@router.get("/computers/{id}/activity")
def computer_activity(id: str, page: int = 1, pageSize: int = 25, ctx: Ctx = Depends(get_ctx),
                      user=Depends(guard(P.AD_COMPUTERS_READ, module=MODULE))):
    require_logs_access(ctx, user)
    return ok(ObjectActivity(ctx.db, user).for_object(str(gid(id)), page, pageSize))


@router.post("/computers/{id}/enable")
def computer_enable(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                    _=Depends(guard(P.AD_COMPUTERS_ENABLE, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.set_computer_enabled(gid(id), True, svc.ChangeInput.from_dict(body)))


@router.post("/computers/{id}/disable")
def computer_disable(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                     _=Depends(guard(P.AD_COMPUTERS_DISABLE, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.set_computer_enabled(gid(id), False, svc.ChangeInput.from_dict(body)))


@router.post("/computers/{id}/move")
def computer_move(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                  _=Depends(guard(P.AD_COMPUTERS_MOVE, module=MODULE, rate="write"))):
    return change_response(svc.ad_services(ctx).changes.move(gid(id), ObjectKind.Computer, svc.MoveRequest.from_dict(body)))


# ---------------------------------------------------------------------------------- groups

@router.get("/groups")
def groups_search(q: str | None = None, page: int = 1, pageSize: int = 25, ctx: Ctx = Depends(get_ctx),
                  _=Depends(guard(P.AD_GROUPS_READ, module=MODULE, rate="search"))):
    return ok(svc.ad_services(ctx).directory.search_groups(q, page, pageSize))


@router.get("/groups/{id}")
def group_get(id: str, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_GROUPS_READ, module=MODULE))):
    g = svc.ad_services(ctx).directory.get_group(gid(id))
    return ok(g) if g else problem(404, "Not found", "Group not found in the directory.")


@router.get("/groups/{id}/members/export")
def group_members_export(id: str, q: str | None = None, kind: str | None = None, ctx: Ctx = Depends(get_ctx),
                         _=Depends(guard(P.AD_GROUPS_MEMBER_EXPORT, module=MODULE))):
    group_id = gid(id)
    k = enum_param(MemberKind, kind, None)
    ad = svc.ad_services(ctx).directory
    group = ad.get_group(group_id)
    if group is None:
        return problem(404, "Not found", "Group not found in the directory.")
    limit = ctx.config.app.export_row_limit
    probe = ad.search_members(group_id, q, k, 1, 1)
    filter_text = f"filter '{q}', type {k.name if k else 'All'}"
    if probe.total > limit:
        ctx.audit.write(AuditEntry(action="ad.groups.member.export", module=MODULE, target=group.name, target_id=str(group_id),
                                   result=AuditResult.FAILURE, error=f"{probe.total} rows exceed the export limit of {limit}", new_value=filter_text))
        return problem(400, "Too many rows", f"This export has {probe.total} rows, more than the limit of {limit}. Narrow the filter and try again.")
    ctx.audit.write(AuditEntry(action="ad.groups.member.export", module=MODULE, target=group.name, target_id=str(group_id),
                               new_value=f"{probe.total} rows, {filter_text}"))

    def rows():
        page = 1
        while True:
            r = ad.search_members(group_id, q, k, page, 500)
            for m in r.items:
                yield [m.name, m.sam_account_name, m.email, m.kind.name, "" if m.enabled is None else str(m.enabled), m.dn]
            if page * 500 >= r.total or not r.items:
                return
            page += 1

    slug = re.sub(r"[^0-9A-Za-z]", "-", group.name)
    name = f"group-members-{slug}-{datetime.now(UTC):%Y%m%d-%H%M}.csv"
    return StreamingResponse(csv_writer.stream(["Name", "Username", "Email", "Type", "Enabled", "Distinguished name"], rows()),
                             media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/groups/{id}/members")
def group_members(id: str, q: str | None = None, kind: str | None = None, page: int = 1, pageSize: int = 50, ctx: Ctx = Depends(get_ctx),
                  _=Depends(guard(P.AD_GROUPS_READ, module=MODULE, rate="search"))):
    """Server-side member search and paging: the directory filters, this never loads the whole member list."""
    return ok(svc.ad_services(ctx).directory.search_members(gid(id), q, enum_param(MemberKind, kind, None), page, pageSize))


@router.get("/groups/{id}/addable-users")
def group_addable_users(id: str, q: str | None = None, ctx: Ctx = Depends(get_ctx),
                        _=Depends(guard(P.AD_USERS_GROUPS_ADD, module=MODULE, rate="search"))):
    """Users that could be added to this group, matching the search text, flagged when already a direct member."""
    text = (q or "").strip()
    if len(text) < 2:
        return ok([])
    ad = svc.ad_services(ctx).directory
    users = ad.search_users(text, UserFilter.All, 1, 20, None)
    members = ad.search_members(gid(id), text, MemberKind.User, 1, 200)
    member_ids = {m.id for m in members.items}
    return ok([{"id": u.id, "name": u.display_name or u.sam_account_name, "samAccountName": u.sam_account_name, "email": u.email,
                "enabled": u.enabled, "alreadyMember": u.id in member_ids} for u in users.items])


@router.post("/groups/{id}/members/add")
def group_members_add(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                      _=Depends(guard(P.AD_USERS_GROUPS_ADD, module=MODULE, rate="write"))):
    return ok({"results": svc.ad_services(ctx).changes.change_group_members(gid(id), True, svc.GroupMembersRequest.from_dict(body))})


@router.post("/groups/{id}/members/remove")
def group_members_remove(id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx),
                         _=Depends(guard(P.AD_USERS_GROUPS_REMOVE, module=MODULE, rate="write"))):
    return ok({"results": svc.ad_services(ctx).changes.change_group_members(gid(id), False, svc.GroupMembersRequest.from_dict(body))})


# ---------------------------------------------------------------------------------- OUs

@router.get("/ous")
def ous_browse(parent: str | None = None, q: str | None = None, kind: str | None = None, ctx: Ctx = Depends(get_ctx),
               _=Depends(guard(*P.AD_OU_BROWSE, module=MODULE))):
    """Lazy OU tree. Pass parent to expand a node, or q to search by name."""
    k = enum_param(ObjectKind, kind, ObjectKind.User)
    return ok(svc.ad_services(ctx).directory.browse_ous(parent, k, q))


# ---------------------------------------------------------------------------------- hourly insights

MAX_LOCKOUTS = 5000


@router.get("/activity/hourly")
def hourly(hours: int = 24, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.AD_USERS_READ, module=MODULE))):
    """Hour-by-hour counts for the Home chart: password resets and unlocks done through this application, and account lockouts recorded in AD."""
    hours = min(max(hours, 6), 72)
    now = utcnow()
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)  # exclusive: the current, unfinished hour is the last bar
    start = end - timedelta(hours=hours)

    rows = ctx.db.execute(select(AuditLog.time_utc, AuditLog.action).where(
        AuditLog.time_utc >= start, AuditLog.result == AuditResult.SUCCESS,
        AuditLog.action.in_(["ad.user.resetPassword", "ad.user.unlock"]))).all()
    rows = [(t if t.tzinfo else t.replace(tzinfo=UTC), a) for t, a in rows]

    note = None
    lockouts: list[datetime] = []
    try:
        lockouts = ctx.state.provider.lockout_times(start, MAX_LOCKOUTS)
    except (DirectoryUnavailableError, ModuleUnavailableError):
        note = "Lockouts could not be read because the directory is unreachable."
    if len(lockouts) >= MAX_LOCKOUTS:
        note = f"Lockouts are capped at {MAX_LOCKOUTS}."

    points = []
    for i in range(hours):
        h = start + timedelta(hours=i)
        nxt = h + timedelta(hours=1)
        points.append({
            "hourUtc": h,
            "passwordResets": sum(1 for t, a in rows if a == "ad.user.resetPassword" and h <= t < nxt),
            "unlocks": sum(1 for t, a in rows if a == "ad.user.unlock" and h <= t < nxt),
            "lockouts": sum(1 for t in lockouts if h <= t < nxt),
        })
    return ok({"hours": hours, "points": points, "totalPasswordResets": sum(p["passwordResets"] for p in points),
               "totalUnlocks": sum(p["unlocks"] for p in points), "totalLockouts": sum(p["lockouts"] for p in points), "lockoutsNote": note})


# ---------------------------------------------------------------------------------- settings (AD Integration)

_ATTRIBUTE = re.compile(r"\A[A-Za-z][A-Za-z0-9-]{0,63}\Z")


@router.get("/settings")
def settings_get(ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.SETTINGS_READ, module=MODULE))):
    o = ctx.config.ad
    s = svc.ad_services(ctx)
    return ok({
        # Read-only: these come from the configuration files, not the database.
        "connection": {
            "provider": ctx.state.provider.provider_name, "domain": o.domain, "server": o.server, "port": o.port,
            "securityMode": ("LDAPS (certificate verified)" if o.verify_certificate else "LDAPS (certificate NOT verified)") if o.use_ldaps else "Plain LDAP",
            "baseDn": ctx.state.provider.base_dn,
        },
        "settings": s.settings.get(),
    })


def _validate(ctx: Ctx, v: AdSettings) -> AdSettings:
    base_dn = ctx.state.provider.base_dn

    def dns(items, label: str) -> list[str]:
        out: list[str] = []
        for raw in items or []:
            dn = (raw or "").strip()
            if not dn:
                continue
            if not is_valid_dn(dn):
                raise ApiException(400, "Invalid distinguished name", f"'{dn}' in {label} is not a valid distinguished name.", "validation")
            if not is_under_or_equal(dn, base_dn):
                raise ApiException(400, "Outside the domain", f"'{dn}' in {label} is not inside {base_dn}.", "validation")
            if not any(dn_equal(x, dn) for x in out):
                out.append(dn)
        return out

    employee = "employeeID" if not (v.employee_id_attribute or "").strip() else v.employee_id_attribute.strip()
    if not _ATTRIBUTE.match(employee):
        raise ApiException(400, "Invalid attribute", "The employee ID attribute must be a plain attribute name such as employeeID.", "validation")
    last_user = None if not (v.computer_last_user_attribute or "").strip() else v.computer_last_user_attribute.strip()
    if last_user is not None and not _ATTRIBUTE.match(last_user):
        raise ApiException(400, "Invalid attribute", "The last logged-in user attribute must be a plain attribute name.", "validation")
    if v.search_result_limit < 50 or v.search_result_limit > 5000:
        raise ApiException(400, "Invalid limit", "The search result limit must be between 50 and 5000.", "validation")

    seen: set[str] = set()
    protected_groups = []
    for x in v.protected_groups or []:
        t = (x or "").strip()
        if t and t.upper() not in seen:
            seen.add(t.upper())
            protected_groups.append(t)
    return AdSettings(
        dns(v.manageable_user_ous, "manageable user OUs"), dns(v.manageable_computer_ous, "manageable computer OUs"),
        dns(v.protected_ous, "protected OUs"), dns(v.manageable_groups, "manageable groups"), protected_groups,
        employee, last_user, v.search_result_limit)


@router.put("/settings")
def settings_put(body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.SETTINGS_MANAGE, module=MODULE))):
    cleaned = _validate(ctx, AdSettings.from_dict(body))
    before, after = svc.ad_services(ctx).settings.save(cleaned, user.display_name)
    ctx.audit.write(AuditEntry(action="settings.ad.update", module=MODULE, target="AD Integration settings", previous_value=before, new_value=after))
    return ok({"settings": cleaned})


@router.post("/settings/test-connection")
def settings_test_connection(ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.SETTINGS_MANAGE, module=MODULE))):
    result = ctx.state.provider.test_connection()
    ctx.audit.write(AuditEntry(
        action="settings.ad.testConnection", module=MODULE, target="AD connection",
        result=AuditResult.SUCCESS if result.success else AuditResult.FAILURE,
        new_value="; ".join(f"{s.name}: {'ok' if s.passed else 'FAILED'}" for s in result.steps)))
    return ok(result)


@router.get("/settings/groups")
def settings_groups(q: str | None = None, page: int = 1, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.SETTINGS_MANAGE, module=MODULE))):
    """Group picker for the allowlist editor (users without ad.groups.read can still manage settings)."""
    return ok(svc.ad_services(ctx).directory.search_groups(q, page, 25))
