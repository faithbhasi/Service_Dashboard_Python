from __future__ import annotations

from fastapi import APIRouter, Depends

from ..http_helpers import ok, problem
from ..web import Ctx, get_ctx, guard

router = APIRouter(prefix="/api/search")
MIN_LENGTH = 2
MAX_LENGTH = 100


@router.get("")
def search(q: str | None = None, ctx: Ctx = Depends(get_ctx), user=Depends(guard(authenticated_only=True, rate="search"))):
    """Asks every enabled module for results. There is no permission of its own: each module only searches and returns the
    categories the caller may read, so a user with no read permissions simply gets nothing back."""
    query = (q or "").strip()
    if len(query) < MIN_LENGTH:
        return problem(400, "Search text too short", f"Type at least {MIN_LENGTH} characters.")
    if len(query) > MAX_LENGTH:
        query = query[:MAX_LENGTH]
    results = []
    for hook in ctx.state.hooks:
        if not ctx.modules.is_enabled(hook.module_id):
            continue
        categories = hook.search(ctx, query, user)
        if categories:
            results.append({"moduleId": hook.module_id, "categories": categories})
    return ok({"query": query, "modules": results})
