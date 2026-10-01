"""Sign-in, sign-out, the current user, preferences and the page-access log."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy import select
from starlette.responses import RedirectResponse

from .. import permissions as P
from ..access import parse_groups
from ..audit import AuditEntry
from ..db import AppUser, AuditCategory, AuditResult, UserRole
from ..errors import ApiException
from ..http_helpers import no_content, ok, problem
from ..logging_setup import get_logger
from ..sessions import rotate_session
from ..user_provisioning import UserProvisioning
from ..web import Ctx, get_ctx, guard

log = get_logger("auth")
router = APIRouter(prefix="/api/auth")
oidc_router = APIRouter()  # the browser-facing callbacks live outside /api, at the paths registered with Okta


def dev_sign_in(ctx: Ctx) -> bool:
    return ctx.config.okta.development_sign_in and ctx.config.is_development


def _is_local_url(url: str | None) -> bool:
    return bool(url) and url.startswith("/") and not url.startswith("//") and not url.startswith("/\\")


@router.get("/config")
def get_config(ctx: Ctx = Depends(get_ctx)):
    """Public bootstrap info for the login page. Also hands out the anti-forgery token for anonymous posts."""
    general = ctx.settings.general()
    return ok({"devSignIn": dev_sign_in(ctx), "productName": general.product_name, "csrfToken": ctx.csrf_token()})


@router.get("/login")
async def login(request: Request, returnUrl: str | None = None, ctx: Ctx = Depends(get_ctx)):
    target = returnUrl if _is_local_url(returnUrl) else "/"
    if dev_sign_in(ctx):
        return RedirectResponse("/login", status_code=302)
    oauth = ctx.state.oauth
    if oauth is None:
        return problem(503, "Sign-in is not configured", "Okta settings are missing.", "not_configured")
    request.session["return_url"] = target
    redirect_uri = str(request.base_url).rstrip("/") + "/signin-oidc"
    return await oauth.okta.authorize_redirect(request, redirect_uri)


@router.get("/dev-users")
def dev_users(ctx: Ctx = Depends(get_ctx)):
    if not dev_sign_in(ctx):
        return problem(404, "Not Found")
    users = ctx.db.scalars(select(AppUser).where(AppUser.subject.like("dev|%")).order_by(AppUser.display_name)).all()
    out = []
    for u in users:
        roles = [ur.role.name for ur in ctx.db.scalars(select(UserRole).where(UserRole.user_id == u.id))]
        out.append({"id": u.id, "displayName": u.display_name, "email": u.email, "isEnabled": u.is_enabled, "roles": roles})
    return ok(out)


@router.post("/dev-login")
def dev_login(request: Request, body: dict = Body(...), _=Depends(guard(anonymous=True)), ctx: Ctx = Depends(get_ctx)):
    if not dev_sign_in(ctx):
        return problem(404, "Not Found")
    user = ctx.db.scalar(select(AppUser).where(AppUser.id == str(body.get("userId", "")).lower(), AppUser.subject.like("dev|%")))
    if user is None:
        return problem(404, "Unknown development user")
    outcome = ctx.provisioning.sign_in(user.subject, user.email, user.display_name, sorted(parse_groups(user.okta_groups_json)))
    if outcome.user is None:
        return problem(403, "Access disabled", "This user is disabled in the app.")
    UserProvisioning.start_session(request.session, outcome.user)
    rotate_session(request)
    return ok({"ok": True})


@router.post("/logout")
async def logout(request: Request, ctx: Ctx = Depends(get_ctx)):
    """Posted by a normal HTML form so the browser can follow the redirect to Okta's sign-out page."""
    supplied = None
    ctype = request.headers.get("content-type", "")
    if "form" in ctype:
        supplied = (await request.form()).get("__RequestVerificationToken")
    ctx.verify_csrf(supplied if supplied is None else str(supplied))
    user = ctx.user()
    if user is not None:
        ctx.audit.write(AuditEntry(action="logon.signout", category=AuditCategory.Logon))
    id_token = request.session.get("id_token")
    request.session.clear()
    if dev_sign_in(ctx) or ctx.state.oauth is None:
        return RedirectResponse("/login?signedOut=1", status_code=302)
    try:
        meta = await ctx.state.oauth.okta.load_server_metadata()
        end = meta.get("end_session_endpoint")
    except Exception:
        end = None
    if not end:
        return RedirectResponse("/login?signedOut=1", status_code=302)
    q = {"post_logout_redirect_uri": str(request.base_url).rstrip("/") + "/signout-callback-oidc"}
    if id_token:
        q["id_token_hint"] = id_token
    return RedirectResponse(end + "?" + urlencode(q), status_code=302)


@oidc_router.get("/signin-oidc")
async def signin_callback(request: Request, ctx: Ctx = Depends(get_ctx)):
    """Okta sends the browser back here with the authorization code (response_mode=query, PKCE)."""
    oauth = ctx.state.oauth
    if oauth is None:
        return RedirectResponse("/login?error=failed", status_code=302)
    target = request.session.get("return_url") or "/"
    try:
        token = await oauth.okta.authorize_access_token(request)
        claims = dict(token.get("userinfo") or {})
        subject = claims.get("sub")
        if not subject:
            raise ValueError("missing subject")
    except Exception as ex:  # OAuthError, validation failures, network problems
        reason = "Access denied by Okta" if "access_denied" in str(ex).lower() else "Sign-in could not be completed"
        ctx.audit.write(AuditEntry(action="logon.failed", category=AuditCategory.Logon, result=AuditResult.FAILURE, error=reason))
        log.warning("OIDC sign-in failed: %s", type(ex).__name__)
        request.session.clear()
        return RedirectResponse("/login?error=failed", status_code=302)

    claim = ctx.config.okta.groups_claim or "groups"
    raw_groups = claims.get(claim) or []
    groups = [raw_groups] if isinstance(raw_groups, str) else [str(g) for g in raw_groups]
    outcome = ctx.provisioning.sign_in(str(subject), claims.get("email") or claims.get("preferred_username"), claims.get("name"), groups)
    if outcome.user is None:
        request.session.clear()
        return RedirectResponse("/login?error=disabled", status_code=302)
    # Keep only the ID token (needed to sign out of Okta). Access and refresh tokens are dropped.
    UserProvisioning.start_session(request.session, outcome.user, id_token=token.get("id_token"))
    rotate_session(request)
    return RedirectResponse(target if _is_local_url(target) else "/", status_code=302)


@oidc_router.get("/signout-callback-oidc")
def signout_callback():
    return RedirectResponse("/login?signedOut=1", status_code=302)


@router.get("/me")
def me(user=Depends(guard(authenticated_only=True)), ctx: Ctx = Depends(get_ctx)):
    general = ctx.settings.general()
    return ok({
        "id": user.id, "displayName": user.display_name, "email": user.email, "initials": user.initials, "hasAccess": user.has_access,
        "roles": [{"id": r.id, "name": r.name, "source": r.source} for r in user.roles],
        "roleName": ", ".join(r.name for r in user.roles),
        "permissions": sorted(user.permissions),
        "preferences": {"theme": user.theme_preference, "navCollapsed": user.nav_collapsed},
        "supportContact": general.support_contact, "csrfToken": ctx.csrf_token(),
    })


@router.put("/preferences")
def set_preferences(body: dict = Body(...), user=Depends(guard(authenticated_only=True)), ctx: Ctx = Depends(get_ctx)):
    theme = body.get("theme")
    if theme not in ("light", "dark", "system"):
        return problem(400, "Theme must be light, dark or system")
    row = ctx.db.get(AppUser, user.id)
    row.theme_preference = theme
    row.nav_collapsed = bool(body.get("navCollapsed", False))
    ctx.db.commit()
    return no_content()


@router.post("/access")
def record_access(body: dict = Body(...), user=Depends(guard(authenticated_only=True)), ctx: Ctx = Depends(get_ctx)):
    """Records that the user opened a page (Application Access log) and whether they were allowed."""
    page = str(body.get("page", ""))
    required = P.PAGE_ACCESS.get(page)
    if required is None:
        return problem(400, "Unknown page")
    allowed = len(required) == 0 or user.has_any(*required)
    ctx.audit.write(AuditEntry(
        action="page.view", category=AuditCategory.Access, module="ad" if page.startswith("ad.") else "core", target=page,
        result=AuditResult.SUCCESS if allowed else AuditResult.DENIED, error=None if allowed else "Missing permission"))
    return ok({"allowed": allowed})


__all__ = ["router", "oidc_router", "ApiException"]
