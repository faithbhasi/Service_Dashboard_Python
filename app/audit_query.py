"""Filtering, paging and scoping for the Activity and Logs area. The audit table is only ever read here, never edited."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, and_, func, select
from sqlalchemy.orm import Session

from .db import AuditCategory, AuditLog
from .util import iso, like_pattern

LIST_VALUE_LIMIT = 300


@dataclass
class LogFilter:
    from_: datetime | None = None
    to: datetime | None = None
    user_id: str | None = None
    action: str | None = None
    result: str | None = None
    target: str | None = None
    ticket: str | None = None
    module: str | None = None
    target_id: str | None = None


def apply_filter(q: Select, f: LogFilter) -> Select:
    if f.from_ is not None:
        q = q.where(AuditLog.time_utc >= f.from_)
    if f.to is not None:
        q = q.where(AuditLog.time_utc <= f.to)
    if f.user_id:
        q = q.where(AuditLog.user_id == f.user_id)
    if f.action and f.action.strip():
        q = q.where(AuditLog.action.like(like_pattern(f.action), escape="\\"))
    if f.result and f.result.strip():
        q = q.where(AuditLog.result == f.result)
    if f.target and f.target.strip():
        q = q.where(and_(AuditLog.target.is_not(None), AuditLog.target.like(like_pattern(f.target), escape="\\")))
    if f.ticket and f.ticket.strip():
        q = q.where(and_(AuditLog.ticket_number.is_not(None), AuditLog.ticket_number.like(like_pattern(f.ticket), escape="\\")))
    if f.module and f.module.strip():
        q = q.where(AuditLog.module == f.module)
    if f.target_id and f.target_id.strip():
        q = q.where(AuditLog.target_id == f.target_id)
    return q


def for_category(q: Select, tab: str | None) -> Select:
    cat = {"logons": AuditCategory.Logon, "access": AuditCategory.Access, "admin": AuditCategory.Admin}.get(tab or "")
    return q if cat is None else q.where(AuditLog.category == cat)  # user-activity: every category


def to_row(a: AuditLog, full: bool = False) -> dict:
    def clip(v: str | None) -> str | None:
        return v if full or v is None or len(v) <= LIST_VALUE_LIMIT else v[:LIST_VALUE_LIMIT]

    return {
        "id": a.id, "timeUtc": iso(a.time_utc), "category": a.category.name, "userId": a.user_id, "userName": a.user_name, "action": a.action,
        "module": a.module, "target": a.target, "targetId": a.target_id, "previousValue": clip(a.previous_value), "newValue": clip(a.new_value),
        "result": a.result, "error": a.error, "justification": a.justification, "ticketNumber": a.ticket_number, "ipAddress": a.ip_address,
        "userAgent": a.user_agent, "correlationId": a.correlation_id,
    }


CSV_HEADER = ["Time (UTC)", "Category", "User", "Action", "Module", "Target", "Target ID", "Previous value", "New value", "Result", "Error",
              "Justification", "Ticket", "IP address", "Browser", "Correlation ID"]


def csv_row(a: AuditLog) -> list[str | None]:
    return [a.time_utc.strftime("%Y-%m-%d %H:%M:%S"), a.category.name, a.user_name, a.action, a.module, a.target, a.target_id, a.previous_value,
            a.new_value, a.result, a.error, a.justification, a.ticket_number, a.ip_address, a.user_agent, a.correlation_id]


def page_of(db: Session, q: Select, page: int, page_size: int, full: bool = False) -> dict:
    total = db.scalar(select(func.count()).select_from(q.order_by(None).subquery())) or 0
    rows = db.scalars(q.order_by(AuditLog.time_utc.desc(), AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [to_row(a, full) for a in rows], "total": total, "page": page, "pageSize": page_size}


class ObjectActivity:
    """Audit history of one object (by target id, for AD the objectGUID), for the Activity History tab in pop-ups."""

    def __init__(self, db: Session, user):
        self.db = db
        self.user = user

    def for_object(self, target_id: str, page: int, page_size: int) -> dict:
        from . import permissions as P

        page_size = max(1, min(page_size, 100))
        page = max(1, page)
        q = select(AuditLog).where(AuditLog.category == AuditCategory.Admin, AuditLog.target_id == target_id)
        if not self.user.has(P.LOGS_READ):
            q = q.where(AuditLog.user_id == self.user.id)
        return page_of(self.db, q, page, page_size)
