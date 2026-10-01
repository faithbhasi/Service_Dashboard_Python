"""Activity and Logs. Read-only over the append-only audit table. People with only logs.read.own see nothing but their own activity;
the scope is applied here on the server, whatever the query string says."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from starlette.responses import StreamingResponse

from .. import csv_writer, permissions as P
from ..audit import AuditEntry
from ..audit_query import CSV_HEADER, LogFilter, apply_filter, csv_row, for_category, page_of, to_row
from ..db import AppUser, AuditLog, AuditResult
from ..errors import ApiException
from ..http_helpers import ok, problem
from ..util import as_utc, iso, parse_guid
from ..web import Ctx, get_ctx, guard

router = APIRouter(prefix="/api/logs")
TABS = ["logons", "access", "admin", "user-activity"]


def _dt(v: str | None) -> datetime | None:
    if not v or not v.strip():
        return None
    try:
        return as_utc(datetime.fromisoformat(v.strip().replace("Z", "+00:00")))
    except ValueError:
        raise ApiException(400, "Invalid date", f"'{v}' is not a valid date and time.", "validation") from None


def read_filter(request: Request) -> LogFilter:
    q = request.query_params
    uid = q.get("userId")
    if uid and parse_guid(uid) is None:
        raise ApiException(400, "Invalid user", "The user id is not valid.", "validation")
    return LogFilter(from_=_dt(q.get("from")), to=_dt(q.get("to")), user_id=str(parse_guid(uid)) if uid else None, action=q.get("action"),
                     result=q.get("result"), target=q.get("target"), ticket=q.get("ticket"), module=q.get("module"), target_id=q.get("targetId"))


def _paging(request: Request, default_size: int = 25) -> tuple[int, int]:
    def num(key: str, default: int) -> int:
        try:
            return int(request.query_params.get(key, default))
        except ValueError:
            return default

    return max(1, num("page", 1)), max(1, min(num("pageSize", default_size), 200))


def _scope(q, user, all_logs: bool):
    return q if all_logs else q.where(AuditLog.user_id == user.id)


def describe(tab: str, f: LogFilter) -> str:
    parts = []
    if f.from_:
        parts.append(f"from {f.from_:%Y-%m-%d %H:%M:%SZ}")
    if f.to:
        parts.append(f"to {f.to:%Y-%m-%d %H:%M:%SZ}")
    if f.user_id:
        parts.append(f"user {f.user_id}")
    if f.action and f.action.strip():
        parts.append(f"action '{f.action}'")
    if f.result and f.result.strip():
        parts.append(f"result {f.result}")
    if f.target and f.target.strip():
        parts.append(f"target '{f.target}'")
    if f.ticket and f.ticket.strip():
        parts.append(f"ticket '{f.ticket}'")
    if f.module and f.module.strip():
        parts.append(f"module {f.module}")
    return ", ".join(parts) if parts else "no filters"


# literal routes first, so "users" and "users-by" are never taken for a tab name

@router.get("/users")
def users(q: str | None = None, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.LOGS_READ))):
    """App users to pick from on the User Activity tab."""
    query = select(AppUser)
    if q and q.strip():
        t = f"%{q.strip().lower()}%"
        query = query.where(func.lower(AppUser.display_name).like(t) | func.lower(AppUser.email).like(t))
    rows = ctx.db.scalars(query.order_by(AppUser.display_name).limit(25)).all()
    return ok([{"id": u.id, "displayName": u.display_name, "email": u.email} for u in rows])


@router.get("/users-by")
def users_by(request: Request, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.LOGS_READ))):
    """Everyone who accessed a module or performed an action in a date range."""
    f = read_filter(request)
    q = apply_filter(select(AuditLog.user_id, AuditLog.user_name, func.count(), func.max(AuditLog.time_utc)).where(AuditLog.user_id.is_not(None)), f)
    rows = ctx.db.execute(q.group_by(AuditLog.user_id, AuditLog.user_name).order_by(func.count().desc()).limit(500)).all()
    return ok([{"userId": r[0], "userName": r[1], "count": r[2], "lastUtc": iso(r[3])} for r in rows])


@router.get("/entry/{entry_id}")
def detail(entry_id: int, ctx: Ctx = Depends(get_ctx), user=Depends(guard(*P.LOGS_ACCESS))):
    q = _scope(select(AuditLog).where(AuditLog.id == entry_id), user, user.has(P.LOGS_READ))
    row = ctx.db.scalar(q)
    return problem(404, "Not Found") if row is None else ok(to_row(row, full=True))


@router.get("/{tab}/export")
def export(tab: str, request: Request, ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.LOGS_EXPORT))):
    """CSV of the current filtered view, generated in the request. Capped, audited, and protected against formula injection."""
    if tab not in TABS:
        return problem(404, "Not Found")
    all_logs = user.has(P.LOGS_READ)
    f = read_filter(request)
    if not all_logs and tab == "user-activity":
        f.user_id = user.id
    if not user.has_any(P.LOGS_READ, P.LOGS_READ_OWN):
        return problem(403, "Access denied", "You cannot read logs.")
    q = apply_filter(for_category(_scope(select(AuditLog), user, all_logs), tab), f)
    total = ctx.db.scalar(select(func.count()).select_from(q.subquery())) or 0
    limit = ctx.config.app.export_row_limit
    description = describe(tab, f)
    if total > limit:
        ctx.audit.write(AuditEntry(action="logs.export", module="core", target=f"Logs: {tab}", result=AuditResult.FAILURE,
                                   error=f"{total} rows exceed the export limit of {limit}", new_value=description))
        return problem(400, "Too many rows", f"This export has {total} rows, more than the limit of {limit}. Narrow the filter (for example a shorter date range) and try again.")
    ctx.audit.write(AuditEntry(action="logs.export", module="core", target=f"Logs: {tab}", new_value=f"{total} rows; {description}"))

    factory = ctx.state.factory
    ordered = q.order_by(AuditLog.time_utc.desc(), AuditLog.id.desc())

    def rows():
        with factory() as db:  # its own session, so the stream does not depend on the request's session lifetime
            for a in db.scalars(ordered).yield_per(500):
                yield csv_row(a)

    from datetime import UTC
    from datetime import datetime as _dt_

    name = f"activity-{tab}-{_dt_.now(UTC):%Y%m%d-%H%M}.csv"
    return StreamingResponse(csv_writer.stream(CSV_HEADER, rows()), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/{tab}")
def list_logs(tab: str, request: Request, ctx: Ctx = Depends(get_ctx), user=Depends(guard(*P.LOGS_ACCESS))):
    if tab not in TABS:
        return problem(404, "Not Found")
    all_logs = user.has(P.LOGS_READ)
    f = read_filter(request)
    if tab == "user-activity" and not all_logs:
        f.user_id = user.id  # own timeline only
    page, size = _paging(request)
    q = apply_filter(for_category(_scope(select(AuditLog), user, all_logs), tab), f)
    return ok(page_of(ctx.db, q, page, size))
