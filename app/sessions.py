"""Server-side sessions.

The browser holds one HttpOnly cookie with an opaque random id. Everything else (who is signed in, when they signed in and were last
active, the anti-forgery token, the Okta ID token needed for sign-out) lives in the database, so nothing sensitive is ever in the cookie
and a session can be revoked on the server. The session dict is available as ``request.session``.
"""
from __future__ import annotations

import json
import secrets
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .db import UserSession
from .util import utcnow

COOKIE = "sd.session"
OUTER_LIMIT = timedelta(hours=24)  # the real idle and absolute limits come from Settings; this is only the outer bound


class SessionMiddleware:
    def __init__(self, app: ASGIApp, factory: sessionmaker, secure_cookie: bool):
        self.app = app
        self.factory = factory
        self.secure = secure_cookie

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        conn = HTTPConnection(scope)
        sid = conn.cookies.get(COOKIE)
        data: dict = {}
        known = False
        if sid and 8 <= len(sid) <= 64:
            with self.factory() as db:
                row = db.get(UserSession, sid)
                if row is not None and utcnow() - row.created_utc <= OUTER_LIMIT:
                    try:
                        data = json.loads(row.data)
                        known = True
                    except ValueError:
                        data = {}
        original = json.dumps(data, sort_keys=True)
        scope["session"] = data
        scope["session_state"] = {"rotate": False}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                new_sid = self._persist(scope, sid if known else None, data, original)
                if new_sid == "":  # the session was emptied (signed out): clear the cookie
                    headers = MutableHeaders(scope=message)
                    headers.append("Set-Cookie", f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
                elif new_sid is not None:
                    headers = MutableHeaders(scope=message)
                    cookie = f"{COOKIE}={new_sid}; Path=/; HttpOnly; SameSite=Lax" + ("; Secure" if self.secure else "")
                    headers.append("Set-Cookie", cookie)
                elif sid and not known:
                    headers = MutableHeaders(scope=message)  # an unknown or expired id: clear it
                    headers.append("Set-Cookie", f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _persist(self, scope: Scope, sid: str | None, data: dict, original: str) -> str | None:
        """Saves the session if it changed. Returns the cookie value to send, or None when the cookie is unchanged."""
        state = scope["session_state"]
        current = json.dumps(data, sort_keys=True)
        with self.factory() as db:
            if not data:
                if sid:
                    db.execute(delete(UserSession).where(UserSession.id == sid))
                    db.commit()
                    return ""  # emptied (signed out): the cookie is cleared by the caller below
                return None
            rotate = state["rotate"]
            if sid and not rotate and current == original:
                return None
            if sid and rotate:
                db.execute(delete(UserSession).where(UserSession.id == sid))
                sid = None
            new_sid = sid or secrets.token_urlsafe(32)
            row = db.get(UserSession, new_sid)
            if row is None:
                row = UserSession(id=new_sid, created_utc=utcnow())
                db.add(row)
            row.data = current
            row.user_id = data.get("uid")
            row.updated_utc = utcnow()
            db.commit()
            return new_sid if (sid is None or rotate or new_sid != sid) else None


def rotate_session(request) -> None:
    """Gives the session a fresh id on the next response (done at sign-in, so a pre-login id can never be reused)."""
    request.scope["session_state"]["rotate"] = True


def purge_expired_sessions(factory: sessionmaker) -> int:
    with factory() as db:
        cutoff = utcnow() - OUTER_LIMIT
        n = db.execute(delete(UserSession).where(UserSession.created_utc < cutoff)).rowcount or 0
        db.commit()
        return n


def sessions_of(factory: sessionmaker, user_id: str) -> list[str]:
    with factory() as db:
        return list(db.scalars(select(UserSession.id).where(UserSession.user_id == user_id)))
