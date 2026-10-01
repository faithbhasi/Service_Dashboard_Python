"""The audit trail: one place that writes rows, filling in user, IP, browser and correlation id from the current request."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import sessionmaker

from .db import AuditCategory, AuditLog, AuditResult
from .logging_setup import get_logger
from .request_context import request_info
from .util import utcnow

log = get_logger("audit")


@dataclass
class AuditEntry:
    """What the caller supplies; user, IP, browser and correlation ID are filled from the current request."""

    action: str
    category: AuditCategory = AuditCategory.Admin
    module: str | None = None
    target: str | None = None
    target_id: str | None = None
    previous_value: str | None = None
    new_value: str | None = None
    result: str = AuditResult.SUCCESS
    error: str | None = None
    justification: str | None = None
    ticket_number: str | None = None
    # Set for sign-in events, where there is no authenticated user on the request yet.
    user_id: str | None = None
    user_name: str | None = None


def _trim(s: str | None, n: int) -> str | None:
    return s[:n] if s and len(s) > n else s


class AuditService:
    def __init__(self, factory: sessionmaker):
        self.factory = factory

    def write(self, e: AuditEntry) -> None:
        try:
            info = request_info()
            user_id = e.user_id or (info.user_id if info else None)
            user_name = e.user_name or (info.user_name if info and (e.user_id is None) else None)
            row = AuditLog(
                time_utc=utcnow(), category=e.category, user_id=user_id, user_name=_trim(user_name, 256), action=e.action, module=e.module,
                target=_trim(e.target, 512), target_id=_trim(e.target_id, 128), previous_value=_trim(e.previous_value, 20000),
                new_value=_trim(e.new_value, 20000), result=e.result, error=_trim(e.error, 1000), justification=_trim(e.justification, 2000),
                ticket_number=_trim(e.ticket_number, 100), ip_address=info.ip_address if info else None,
                user_agent=_trim(info.user_agent if info else None, 512), correlation_id=info.correlation_id if info else None,
            )
            with self.factory() as db:  # its own session: an audit row is written even if the request later fails
                db.add(row)
                db.commit()
        except Exception:  # never let an audit failure hide the outcome of the request, but make it visible
            log.exception("Failed to write audit record for %s", e.action)
