"""Per-request plumbing: the Ctx container, authentication, authorization guards, anti-forgery and rate limiting."""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING

from fastapi import Depends, Request
from sqlalchemy.orm import Session, sessionmaker

from . import permissions as P
from .access import AccessService
from .access_management import AccessManagementService, AdScopeCatalog
from .audit import AuditEntry, AuditService
from .config import Settings
from .current_user import CurrentUserInfo
from .db import AppUser, AuditCategory, AuditResult
from .errors import ApiException
from .module_catalog import ModuleCatalog, ModuleDescriptor
from .paths import AppPaths
from .request_context import request_info
from .settings_service import SettingsCache, SettingsService
from .user_provisioning import ACTIVE_CLAIM, SIGN_IN_CLAIM, UID, UserProvisioning

if TYPE_CHECKING:
    from .modules.ad.provider import DirectoryProvider


class RateLimiter:
    """Fixed one-minute window per signed-in user (or per IP address when anonymous)."""

    def __init__(self) -> None:
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, policy: str, key: str, limit: int) -> bool:
        now = time.monotonic()
        with self._lock:
            start, count = self._windows.get((policy, key), (now, 0))
            if now - start >= 60:
                start, count = now, 0
            if count >= limit:
                self._windows[(policy, key)] = (start, count)
                return False
            self._windows[(policy, key)] = (start, count + 1)
            return True


@dataclass
class AppState:
    """Everything that lives for the whole life of the application."""

    config: Settings
    paths: AppPaths
    factory: sessionmaker
    cache: SettingsCache
    audit: AuditService
    modules: list[ModuleDescriptor]
    provider: DirectoryProvider
    limiter: RateLimiter = field(default_factory=RateLimiter)
    dashboard_cache: dict = field(default_factory=dict)
    oauth: object | None = None
    # What each module contributes to the core: search providers and dashboard cards (see ModuleHooks).
    hooks: list = field(default_factory=list)


def app_state(request: Request) -> AppState:
    return request.app.state.sd


class Ctx:
    """One per request: a database session plus lazily-built services and the signed-in user."""

    def __init__(self, request: Request, db: Session):
        self.request = request
        self.db = db
        self.state = app_state(request)
        self._user_loaded = False
        self._user: CurrentUserInfo | None = None

    @property
    def config(self) -> Settings:
        return self.state.config

    @property
    def audit(self) -> AuditService:
        return self.state.audit

    @cached_property
    def settings(self) -> SettingsService:
        return SettingsService(self.db, self.state.cache, self.state.config.app)

    @cached_property
    def access(self) -> AccessService:
        return AccessService(self.db)

    @cached_property
    def modules(self) -> ModuleCatalog:
        return ModuleCatalog(self.state.modules, self.settings)

    @cached_property
    def provisioning(self) -> UserProvisioning:
        return UserProvisioning(self.db, self.audit)

    @cached_property
    def scope_catalog(self) -> AdScopeCatalog | None:
        from .modules.ad.services import build_scope_catalog

        return build_scope_catalog(self) if any(m.id == "ad" for m in self.state.modules) else None

    def access_management(self, user: CurrentUserInfo) -> AccessManagementService:
        return AccessManagementService(self.db, user, self.audit, self.access, self.scope_catalog)

    @property
    def session(self) -> dict:
        return self.request.session

    # ---- authentication

    def user(self) -> CurrentUserInfo | None:
        """The signed-in app user with roles and permissions, or None. Enforces the idle and absolute timeouts and 'still enabled'."""
        if self._user_loaded:
            return self._user
        self._user_loaded = True
        sess = self.session
        uid = sess.get(UID)
        if not uid:
            return None
        row = self.db.get(AppUser, uid)
        if row is None or not row.is_enabled:
            sess.clear()
            return None
        general = self.settings.general()
        now = int(time.time())
        signed_in, active = sess.get(SIGN_IN_CLAIM), sess.get(ACTIVE_CLAIM)
        if (signed_in is None or active is None or now - int(signed_in) > general.absolute_timeout_minutes * 60
                or now - int(active) > general.idle_timeout_minutes * 60):
            sess.clear()
            return None
        if now - int(active) > 60:
            sess[ACTIVE_CLAIM] = now  # sliding idle window, written at most once a minute
        resolved = self.access.resolve(row)
        self._user = CurrentUserInfo(
            id=row.id, subject=row.subject, display_name=row.display_name, email=row.email, is_enabled=row.is_enabled,
            theme_preference=row.theme_preference, nav_collapsed=row.nav_collapsed, roles=resolved.roles,
            permissions=resolved.permissions, ad_scope=resolved.ad_scope)
        info = request_info()
        if info:
            info.user_id, info.user_name = row.id, row.display_name
        return self._user

    # ---- anti-forgery

    def csrf_token(self) -> str:
        sess = self.session
        tok = sess.get("csrf")
        if not tok:
            tok = secrets.token_urlsafe(32)
            sess["csrf"] = tok
        return tok

    def verify_csrf(self, supplied: str | None = None) -> None:
        """Requires a valid anti-forgery token (X-XSRF-TOKEN header or form field) on every state-changing API request."""
        if self.request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return
        expected = self.session.get("csrf")
        got = supplied if supplied is not None else self.request.headers.get("X-XSRF-TOKEN")
        if not expected or not got or not hmac.compare_digest(str(expected), str(got)):
            raise ApiException(400, "Request could not be verified", "The security token is missing or expired. Reload the page and try again.", "antiforgery")

    # ---- rate limiting

    def rate_limit(self, policy: str, user: CurrentUserInfo | None) -> None:
        opts = self.config.app
        limit = opts.search_rate_limit_per_minute if policy == "search" else opts.write_rate_limit_per_minute
        client = self.request.client
        key = f"u:{user.id}" if user else f"ip:{client.host if client else '-'}"
        if not self.state.limiter.allow(policy, key, limit):
            raise ApiException(429, "Too many requests", "Slow down and try again in a minute.", "rate_limited")

    def deny_audit(self) -> None:
        path = self.request.url.path
        parts = [p for p in path.split("/") if p]
        module = parts[2] if len(parts) > 2 and parts[0] == "api" and parts[1] == "modules" else "core"
        self.audit.write(AuditEntry(action="api.access", category=AuditCategory.Access, module=module, target=f"{self.request.method} {path}",
                                    result=AuditResult.DENIED, error="Missing permission"))


def get_ctx(request: Request):
    db = app_state(request).factory()
    try:
        yield Ctx(request, db)
    finally:
        db.close()


def guard(*permissions: str, module: str | None = None, rate: str | None = None, anonymous: bool = False, authenticated_only: bool = False):
    """FastAPI dependency factory.

    permissions: the user needs at least one of them (no permissions + authenticated_only=True means any signed-in user).
    Order mirrors the original application: authentication, rate limit, authorization (a denial is audited), anti-forgery, module gate.
    """

    def dependency(ctx: Ctx = Depends(get_ctx)) -> CurrentUserInfo | None:
        user = ctx.user()
        if anonymous:
            if rate:
                ctx.rate_limit(rate, user)
            ctx.verify_csrf()
            return user
        if user is None:
            raise ApiException(401, "Not signed in", "Sign in to continue.", "unauthenticated")
        if rate:
            ctx.rate_limit(rate, user)
        if permissions and not user.has_any(*permissions):
            ctx.deny_audit()
            raise ApiException(403, "Access denied", "You do not have permission to do this.", "forbidden")
        ctx.verify_csrf()
        if module and not ctx.modules.is_enabled(module):
            raise ApiException(403, "Module disabled", f"The '{module}' module is disabled.", "module_disabled")
        return user

    # Read by the endpoint-authorization test, which proves every route names a permission or is explicitly whitelisted.
    dependency.guard_meta = {"permissions": permissions, "anonymous": anonymous, "authenticated_only": authenticated_only, "module": module}
    return dependency


__all__ = ["AppState", "Ctx", "RateLimiter", "get_ctx", "guard", "app_state", "P"]
