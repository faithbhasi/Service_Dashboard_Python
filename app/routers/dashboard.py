from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from .. import permissions as P
from ..db import AuditCategory, AuditLog, AuditResult
from ..http_helpers import ok
from ..util import iso, utcnow
from ..web import Ctx, get_ctx, guard
from .settings import find_zone

router = APIRouter(prefix="/api/dashboard")
COUNTED = [AuditResult.SUCCESS, AuditResult.FAILURE, AuditResult.DENIED]


@router.get("")
def get_dashboard(ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.DASHBOARD_READ))):
    """Fixed cards. Each one only appears if the user holds the permission that reads the underlying data."""
    cards: list[dict] = []
    for hook in ctx.state.hooks:
        if ctx.modules.is_enabled(hook.module_id):
            cards += hook.dashboard_cards(ctx, user)

    general = ctx.settings.general()
    tz = find_zone(general.time_zone)
    local_now = utcnow().astimezone(tz)
    start_of_today = local_now.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)

    last_actions = None
    if user.has_any(P.LOGS_READ, P.LOGS_READ_OWN):
        all_logs = user.has(P.LOGS_READ)
        admin = AuditLog.category == AuditCategory.Admin
        today_q = select(AuditLog).where(admin, AuditLog.time_utc >= start_of_today, AuditLog.result.in_(COUNTED))
        recent_q = select(AuditLog).where(admin, AuditLog.result != AuditResult.VALIDATED)
        if not all_logs:
            today_q = today_q.where(AuditLog.user_id == user.id)
            recent_q = recent_q.where(AuditLog.user_id == user.id)
        now = utcnow()
        today_count = ctx.db.scalar(select(func.count()).select_from(today_q.subquery())) or 0
        failed = ctx.db.scalar(select(func.count()).select_from(today_q.where(AuditLog.result != AuditResult.SUCCESS).subquery())) or 0
        cards.append({"key": "actionsToday", "title": "Actions performed today" if all_logs else "Your actions today", "count": today_count,
                      "route": "/logs/admin?range=today", "tone": "neutral", "updatedUtc": iso(now)})
        cards.append({"key": "failedToday", "title": "Failed actions today" if all_logs else "Your failed actions today", "count": failed,
                      "route": "/logs/admin?range=today&result=Failure", "tone": "error", "updatedUtc": iso(now)})
        rows = ctx.db.scalars(recent_q.order_by(AuditLog.time_utc.desc(), AuditLog.id.desc()).limit(10)).all()
        last_actions = {
            "title": "Last 10 admin actions" if all_logs else "Your last 10 actions",
            "items": [{"id": a.id, "timeUtc": iso(a.time_utc), "userName": a.user_name, "action": a.action, "target": a.target, "result": a.result} for a in rows],
        }
    return ok({"cards": cards, "lastActions": last_actions})


__all__ = ["router", "datetime"]
