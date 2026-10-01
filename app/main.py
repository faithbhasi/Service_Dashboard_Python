"""Application factory: configuration, startup checks, database, middleware, routers and the React app."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import FileResponse, Response

from . import seed as seeder
from .audit import AuditService
from .config import Settings, load_settings, validate_startup
from .db import create_db_engine, make_session_factory, migrate
from .errors import ApiException, ModuleUnavailableError
from .http_helpers import problem
from .logging_setup import configure_logging, get_logger
from .maintenance import MaintenanceTasks, maintenance_loop
from .middleware import CorrelationIdMiddleware, SecurityHeadersMiddleware
from .module_catalog import ModuleDescriptor
from .modules.ad.fake_provider import FakeDirectoryProvider
from .modules.ad.services import AdHooks
from .paths import AppPaths
from .routers import ALL_ROUTERS
from .sessions import SessionMiddleware, purge_expired_sessions
from .settings_service import SettingsCache
from .web import AppState

log = get_logger("main")
STATIC_DIR = Path(__file__).parent / "static"


def csp_for(settings: Settings) -> str:
    issuer = settings.okta.issuer
    parts = urlsplit(issuer) if issuer else None
    form_action = f" {parts.scheme}://{parts.netloc}" if parts and parts.netloc else ""
    return ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
            f"frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'{form_action}")


def build_oauth(settings: Settings):
    """Okta OpenID Connect (authorization code with PKCE). Not created when development sign-in is used."""
    okta = settings.okta
    if (okta.development_sign_in and settings.is_development) or not (okta.issuer and okta.client_id):
        return None
    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()
    oauth.register(
        "okta", client_id=okta.client_id, client_secret=okta.client_secret or None,
        server_metadata_url=okta.issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": " ".join(okta.scopes), "code_challenge_method": "S256"})
    return oauth


def build_provider(settings: Settings):
    if settings.ad.provider.lower() == "fake":
        return FakeDirectoryProvider(settings.ad.simulate_server_unavailable)
    from .modules.ad.ldap_provider import LdapDirectoryProvider

    return LdapDirectoryProvider(settings.ad)


def create_app(settings: Settings | None = None, provider=None) -> FastAPI:
    settings = settings or load_settings()
    errors = validate_startup(settings)
    if errors:
        raise RuntimeError("The application cannot start:\n - " + "\n - ".join(errors))

    paths = AppPaths(settings)
    paths.ensure_created()
    configure_logging(paths.log_directory)

    engine = create_db_engine(paths.database_file)
    migrate(engine)
    factory = make_session_factory(engine)
    with factory() as db:
        seeder.seed(db, settings)
    purge_expired_sessions(factory)

    audit = AuditService(factory)
    state = AppState(
        config=settings, paths=paths, factory=factory, cache=SettingsCache(), audit=audit,
        modules=[ModuleDescriptor("ad", "Active Directory", "Users, computers and groups in one Active Directory domain.")],
        provider=provider or build_provider(settings), oauth=build_oauth(settings), hooks=[AdHooks()])

    tasks = MaintenanceTasks(factory, paths, settings.app, audit)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        job = asyncio.create_task(maintenance_loop(tasks, settings.app))
        try:
            yield
        finally:
            job.cancel()
            engine.dispose()

    app = FastAPI(title=settings.app.product_name, lifespan=lifespan, docs_url="/api/docs" if settings.is_development else None,
                  redoc_url=None, openapi_url="/api/openapi.json" if settings.is_development else None)
    app.state.sd = state
    app.state.maintenance = tasks

    # ---- errors: always Problem Details, never a stack trace
    @app.exception_handler(ApiException)
    async def _api(_: Request, ex: ApiException):
        return problem(ex.status, ex.title, ex.detail, ex.code)

    @app.exception_handler(ModuleUnavailableError)
    async def _unavailable(_: Request, ex: ModuleUnavailableError):
        logging.getLogger("sd.main").error("Module unavailable: %s", getattr(ex, "technical", ex))
        return problem(503, "Service unavailable", ex.safe_message, "module_unavailable")

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, ex: RequestValidationError):
        return problem(400, "Invalid request", "One or more values in the request are not valid.", "validation")

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, ex: StarletteHTTPException):
        titles = {401: "Not signed in", 403: "Access denied", 404: "Not Found", 405: "Method Not Allowed"}
        return problem(ex.status_code, titles.get(ex.status_code, "Error"))

    # ---- routers (API first, the React app last)
    for r in ALL_ROUTERS:
        app.include_router(r)

    # ---- the React app: static files, and index.html for every non-API route
    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
    def spa(path: str, request: Request):
        if request.method not in ("GET", "HEAD") or path == "api" or path.startswith("api/"):
            return problem(404, "Not Found")
        if STATIC_DIR.is_dir():
            candidate = (STATIC_DIR / path).resolve()
            if path and candidate.is_file() and candidate.is_relative_to(STATIC_DIR.resolve()):
                headers = {"Cache-Control": "public, max-age=31536000, immutable"} if path.startswith("assets/") else {}
                return FileResponse(candidate, headers=headers)
            index = STATIC_DIR / "index.html"
            if index.is_file():
                return FileResponse(index, headers={"Cache-Control": "no-cache"})
        return Response("The front end has not been built. Run: cd frontend && npm install && npm run build", status_code=404, media_type="text/plain")

    # ---- middleware (last added runs first): correlation id, security headers, session, then the app
    app.add_middleware(SessionMiddleware, factory=factory, secure_cookie=not settings.is_development)
    app.add_middleware(SecurityHeadersMiddleware, csp=csp_for(settings), hsts=not settings.is_development)
    app.add_middleware(CorrelationIdMiddleware)
    return app


def app_factory() -> FastAPI:
    """Entry point for `uvicorn app.main:app_factory --factory`."""
    return create_app()
