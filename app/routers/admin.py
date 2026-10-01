"""In-app access management: who can use this application and what they can do. It never touches AD or Okta."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy import func, select
from starlette.responses import StreamingResponse

from .. import csv_writer, permissions as P
from ..access import parse_groups
from ..audit import AuditEntry
from ..db import AppUser, GroupMapping
from ..http_helpers import no_content, ok
from ..models import AdScope
from ..util import iso
from ..web import Ctx, get_ctx, guard

router = APIRouter(prefix="/api/admin")


def _scope_of(body: dict) -> AdScope | None:
    raw = body.get("adScope")
    return None if raw is None else AdScope.from_dict(raw)


# ---------- permissions and roles (read) ----------

@router.get("/permissions")
def get_permissions(ctx: Ctx = Depends(get_ctx), user=Depends(guard(*P.ADMIN_ACCESS))):
    roles = ctx.access_management(user).list_roles()
    return ok([{"id": p.id, "group": p.group, "description": p.description,
                "roles": [r["name"] for r in roles if p.id in r["permissions"]]} for p in P.ALL])


@router.get("/roles")
def get_roles(ctx: Ctx = Depends(get_ctx), user=Depends(guard(*P.ADMIN_ACCESS))):
    return ok(ctx.access_management(user).list_roles())


@router.get("/roles/ad-scope-options")
def ad_scope_options(ctx: Ctx = Depends(get_ctx), _=Depends(guard(*P.ADMIN_ACCESS))):
    """The OUs and groups a role's Active Directory scope can be chosen from (the global manageable lists). Empty when AD is not available."""
    catalog = ctx.scope_catalog
    from ..models import AdScopeOptions

    return ok(catalog.get_options() if catalog else AdScopeOptions())


@router.get("/roles/ad-ou-tree")
def ad_ou_tree(kind: str = "", parent: str | None = None, q: str | None = None, ctx: Ctx = Depends(get_ctx), _=Depends(guard(*P.ADMIN_ACCESS))):
    """The OU tree (lazy) for ticking the OUs a role may manage. Only OUs inside the manageable lists can be chosen."""
    catalog = ctx.scope_catalog
    return ok([] if catalog is None else catalog.browse_ous(kind, parent, q))


# ---------- roles (write) ----------

@router.post("/roles")
def create_role(body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_ROLES_MANAGE))):
    return ok(ctx.access_management(user).create_role(body.get("name") or "", body.get("description"), body.get("permissions") or [], _scope_of(body)))


@router.post("/roles/{role_id}/clone")
def clone_role(role_id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_ROLES_MANAGE))):
    return ok(ctx.access_management(user).clone_role(role_id, body.get("name") or ""))


@router.put("/roles/{role_id}")
def update_role(role_id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_ROLES_MANAGE))):
    return ok(ctx.access_management(user).update_role(role_id, body.get("name") or "", body.get("description"), body.get("permissions") or [], _scope_of(body)))


@router.delete("/roles/{role_id}")
def delete_role(role_id: str, ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_ROLES_MANAGE))):
    ctx.access_management(user).delete_role(role_id)
    return no_content()


# ---------- app users ----------

def _query_users(ctx: Ctx, q: str | None, skip: int, take: int) -> tuple[list[dict], int]:
    query = select(AppUser)
    if q and q.strip():
        t = f"%{q.strip().lower()}%"
        query = query.where(func.lower(AppUser.display_name).like(t) | func.lower(AppUser.email).like(t))
    total = ctx.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    users = list(ctx.db.scalars(query.order_by(AppUser.display_name).offset(skip).limit(take)))
    resolved = ctx.access.resolve_many(users)
    items = [{
        "id": u.id, "displayName": u.display_name, "email": u.email, "isEnabled": u.is_enabled, "createdUtc": iso(u.created_utc),
        "lastSignInUtc": iso(u.last_sign_in_utc),
        "roles": [{"id": r.id, "name": r.name, "source": r.source} for r in resolved[u.id].roles],
        "permissions": sorted(resolved[u.id].permissions), "oktaGroups": sorted(parse_groups(u.okta_groups_json), key=str.lower),
    } for u in users]
    return items, total


@router.get("/users")
def get_users(request: Request, q: str | None = None, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.ADMIN_USERS_MANAGE))):
    try:
        size = int(request.query_params.get("pageSize", 25))
        page = int(request.query_params.get("page", 1))
    except ValueError:
        size, page = 25, 1
    size, page = max(1, min(size, 200)), max(1, page)
    items, total = _query_users(ctx, q, (page - 1) * size, size)
    return ok({"items": items, "total": total, "page": page, "pageSize": size, "totalIsCapped": False})


@router.get("/users/export")
def export_users(q: str | None = None, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.ADMIN_USERS_MANAGE))):
    items, total = _query_users(ctx, q, 0, 100_000)
    ctx.audit.write(AuditEntry(action="admin.users.export", module="core", target="App users",
                               new_value=f"{total} rows" + (f", filter '{q}'" if q and q.strip() else "")))
    from datetime import UTC, datetime

    rows = ([u["displayName"], u["email"], "Enabled" if u["isEnabled"] else "Disabled", u["createdUtc"], u["lastSignInUtc"],
             "; ".join(r["name"] for r in u["roles"]), "; ".join(u["permissions"])] for u in items)
    return StreamingResponse(
        csv_writer.stream(["Name", "Email", "Status", "Created (UTC)", "Last sign-in (UTC)", "Roles", "Effective permissions"], rows),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="app-users-{datetime.now(UTC):%Y%m%d-%H%M}.csv"'})


@router.put("/users/{user_id}/status")
def set_status(user_id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_USERS_MANAGE))):
    ctx.access_management(user).set_user_status(user_id, bool(body.get("isEnabled", False)))
    return no_content()


@router.put("/users/{user_id}/roles")
def set_roles(user_id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_USERS_MANAGE))):
    ctx.access_management(user).set_user_roles(user_id, [str(r).lower() for r in (body.get("roleIds") or [])])
    return no_content()


# ---------- Okta group mappings ----------

@router.get("/group-mappings")
def get_mappings(ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.ADMIN_USERS_MANAGE))):
    rows = ctx.db.scalars(select(GroupMapping).order_by(GroupMapping.okta_group)).all()
    return ok([{"id": m.id, "oktaGroup": m.okta_group, "roleId": m.role_id, "roleName": m.role.name} for m in rows])


@router.post("/group-mappings")
def add_mapping(body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_USERS_MANAGE))):
    m = ctx.access_management(user).add_mapping(body.get("oktaGroup") or "", str(body.get("roleId") or "").lower())
    return ok({"id": m.id, "oktaGroup": m.okta_group, "roleId": m.role_id})


@router.delete("/group-mappings/{mapping_id}")
def delete_mapping(mapping_id: str, ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.ADMIN_USERS_MANAGE))):
    ctx.access_management(user).delete_mapping(mapping_id)
    return no_content()
