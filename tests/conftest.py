"""Test harness: the real application with its own temporary SQLite database and the Fake AD provider,
driven through an in-process HTTP client that keeps cookies and sends anti-forgery tokens like the browser does."""
from __future__ import annotations

import logging
import shutil
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from app import permissions as P
from app.config import _merge, load_settings
from app.db import AppUser, Role
from app.logging_setup import CorrelationFilter, SensitiveDataFilter
from app.main import create_app


class CapturingHandler(logging.Handler):
    """Collects every log line (after redaction) so tests can prove secrets never reach the logs."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []
        self._lock = threading.Lock()
        self.addFilter(SensitiveDataFilter())
        self.addFilter(CorrelationFilter())

    def emit(self, record: logging.LogRecord) -> None:
        with self._lock:
            self.lines.append(self.format(record) + " " + str({k: v for k, v in record.__dict__.items() if k not in logging.LogRecord("", 0, "", 0, "", None, None).__dict__}))

    def all_text(self) -> str:
        with self._lock:
            return "\n".join(self.lines)


class Client:
    """A cookie-keeping client that signs in as a seeded development user and sends the anti-forgery token on writes."""

    def __init__(self, app: TestApp, base_url: str = "http://localhost"):
        self.http = TestClient(app.asgi, base_url=base_url, follow_redirects=False)
        self.csrf = ""
        self.last_sign_in = None

    def sign_in(self, dev_user: str) -> Client:
        self.csrf = self.http.get("/api/auth/config").json()["csrfToken"]
        users = self.http.get("/api/auth/dev-users").json()
        uid = next(u["id"] for u in users if u["email"] == f"{dev_user}@example.invalid")
        res = self.post("/api/auth/dev-login", {"userId": uid})
        if res.status_code == 200:
            self.refresh_csrf()
        self.last_sign_in = res
        return self

    def prime_csrf(self) -> None:
        self.csrf = self.http.get("/api/auth/config").json()["csrfToken"]

    def refresh_csrf(self) -> None:
        me = self.http.get("/api/auth/me")
        if me.status_code == 200:
            self.csrf = me.json()["csrfToken"]

    def get(self, url, **kw):
        return self.http.get(url, **kw)

    def send(self, method: str, url: str, body=None, **kw):
        headers = dict(kw.pop("headers", {}))
        if method != "GET":
            headers["X-XSRF-TOKEN"] = self.csrf
        if body is not None:
            kw["json"] = body
        return self.http.request(method, url, headers=headers, **kw)

    def post(self, url, body=None, **kw):
        return self.send("POST", url, {} if body is None else body, **kw)

    def put(self, url, body=None, **kw):
        return self.send("PUT", url, {} if body is None else body, **kw)

    def delete(self, url, **kw):
        return self.send("DELETE", url, **kw)

    def upload(self, url: str, data: bytes, filename: str, content_type: str = "image/png"):
        return self.http.post(url, files={"file": (filename, data, content_type)}, headers={"X-XSRF-TOKEN": self.csrf})


class TestApp:
    __test__ = False  # not a test class

    def __init__(self, environment: str = "Development", extra: dict | None = None):
        self.root = Path(tempfile.mkdtemp(prefix="sd-tests-"))
        overrides = {
            "App": {"DataDirectory": str(self.root / "data"), "AssetDirectory": str(self.root / "assets"), "BackupDirectory": str(self.root / "backups"),
                    "SearchRateLimitPerMinute": 100000, "WriteRateLimitPerMinute": 100000},
            "Serilog": {"LogDirectory": str(self.root / "logs")},
            "Okta": {"DevelopmentSignIn": True},
            "ActiveDirectory": {"Provider": "Fake"},
        }
        if extra:
            _merge(overrides, extra)
        self.settings = load_settings(environment, overrides)
        try:
            self.asgi = create_app(self.settings)
        except BaseException:
            shutil.rmtree(self.root, ignore_errors=True)
            raise
        self.state = self.asgi.state.sd
        self.logs = CapturingHandler()
        logging.getLogger("sd").addHandler(self.logs)

    def client(self, base_url: str = "http://localhost") -> Client:
        return Client(self, base_url)

    def db(self):
        """A database session for assertions: `with app.db() as db: ...`"""
        return self.state.factory()

    def user_id(self, dev_user: str) -> str:
        with self.db() as db:
            return db.scalars(select(AppUser).where(AppUser.email == f"{dev_user}@example.invalid")).one().id

    def role_id(self, name: str) -> str:
        with self.db() as db:
            return db.scalars(select(Role).where(Role.name == name)).one().id

    def audit(self, **filters):
        from app.db import AuditLog

        with self.db() as db:
            q = select(AuditLog)
            for k, v in filters.items():
                q = q.where(getattr(AuditLog, k) == v)
            return list(db.scalars(q.order_by(AuditLog.id)))

    def close(self) -> None:
        logging.getLogger("sd").removeHandler(self.logs)
        try:
            self.state.factory.kw["bind"].dispose()
        except Exception:
            pass
        shutil.rmtree(self.root, ignore_errors=True)


@pytest.fixture
def app():
    a = TestApp()
    yield a
    a.close()


@pytest.fixture(scope="module")
def shared_app():
    """One app for a whole test module (the equivalent of a class fixture): for tests that only read or add independent data."""
    a = TestApp()
    yield a
    a.close()


@pytest.fixture
def make_app() -> Callable[..., TestApp]:
    created: list[TestApp] = []

    def make(environment: str = "Development", extra: dict | None = None) -> TestApp:
        a = TestApp(environment, extra)
        created.append(a)
        return a

    yield make
    for a in created:
        a.close()


ALL_PERMISSIONS = [p.id for p in P.ALL]
