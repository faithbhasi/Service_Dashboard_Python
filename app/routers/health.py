from fastapi import APIRouter, Depends
from sqlalchemy import text

from ..http_helpers import ok
from ..web import Ctx, get_ctx

router = APIRouter(prefix="/api/health")


@router.get("")
def health(ctx: Ctx = Depends(get_ctx)):
    try:
        ctx.db.execute(text("SELECT 1"))
    except Exception:
        return ok({"status": "database unavailable"}, 503)
    return ok({"status": "ok"})
