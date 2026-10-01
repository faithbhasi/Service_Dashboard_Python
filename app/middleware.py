"""Pure ASGI middleware: correlation id, security headers, and the last-resort error handler."""
from __future__ import annotations

import re
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .http_helpers import problem
from .logging_setup import get_logger
from .request_context import RequestInfo, set_request_info

log = get_logger("http")
HEADER = "X-Correlation-ID"
_VALID = re.compile(r"^[A-Za-z0-9\-_]{8,64}$")


class CorrelationIdMiddleware:
    """Every request gets a correlation ID (reusing a well-formed incoming one) and a RequestInfo for the audit log."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        incoming = headers.get(HEADER, "")
        cid = incoming if _VALID.match(incoming) else uuid.uuid4().hex
        client = scope.get("client")
        info = RequestInfo(correlation_id=cid, ip_address=client[0] if client else None, user_agent=headers.get("user-agent"))
        set_request_info(info)
        scope["correlation_id"] = cid
        started = {"v": False}
        began = time.perf_counter()
        status_holder = {"code": 0}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                started["v"] = True
                status_holder["code"] = message["status"]
                MutableHeaders(scope=message)[HEADER] = cid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            # Unhandled exceptions become a safe Problem Details response. Stack traces never leave the server.
            log.exception("Unhandled exception")
            if not started["v"]:
                resp = problem(500, "Unexpected error", "Something went wrong. Quote the correlation ID when reporting this.", "server_error")
                await resp(scope, receive, send_wrapper)
            status_holder["code"] = 500
        finally:
            path = scope.get("path", "")
            if path.startswith("/api") or status_holder["code"] >= 500:
                lvl = log.error if status_holder["code"] >= 500 else log.info
                lvl("%s %s -> %s in %.1f ms", scope.get("method"), path, status_holder["code"], (time.perf_counter() - began) * 1000)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, csp: str, hsts: bool = False):
        self.app = app
        self.csp = csp
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_api = scope.get("path", "").startswith("/api")
        secure = scope.get("scheme") == "https"

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h["Content-Security-Policy"] = self.csp
                h["X-Content-Type-Options"] = "nosniff"
                h["X-Frame-Options"] = "DENY"
                h["Referrer-Policy"] = "same-origin"
                h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
                if self.hsts and secure:
                    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                if is_api:
                    h["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_wrapper)
