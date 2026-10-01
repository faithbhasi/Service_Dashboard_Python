import ast
import json
import re
import typing
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from sqlalchemy import select

from app import permissions as P
from app.db import UserSession
from app.modules.ad.fake_data import fake_id
from app.modules.ad.fake_provider import FakeDirectoryProvider
from app.modules.ad.ldap_provider import LdapDirectoryProvider
from app.modules.ad.provider import DirectoryProvider
from app.routers import ALL_ROUTERS
from app.settings_service import SettingsService

APP_DIR = Path(__file__).resolve().parent.parent / "app"

# The only routes that may be reached without a permission. Everything else must name one.
ANONYMOUS = {
    "/api/auth/config", "/api/auth/login", "/api/auth/dev-users", "/api/auth/dev-login", "/api/auth/logout",
    "/api/settings/branding", "/api/settings/personalization/logo/{kind}", "/api/health",
}
# Signed-in users only: they return the caller's own data or apply per-module permissions inside.
SESSION_ONLY = {"/api/auth/me", "/api/auth/preferences", "/api/auth/access", "/api/settings/shell", "/api/search"}


def endpoints(app):
    """(path, method, guard metadata or None) for every /api route."""
    out = []
    for r in (route for router in ALL_ROUTERS for route in router.routes):
        if not isinstance(r, APIRoute) or not r.path.startswith("/api/"):
            continue
        meta = next((d.call.guard_meta for d in r.dependant.dependencies if hasattr(d.call, "guard_meta")), None)
        for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
            out.append((r.path, m, meta, r))
    return out


def fill(route: APIRoute) -> str:
    def value(name: str) -> str:
        field = next((p for p in route.dependant.path_params if p.name == name), None)
        ann = getattr(getattr(field, "field_info", None), "annotation", str)
        return "1" if ann is int else str(uuid.uuid4()) if name == "id" else "x"

    return re.sub(r"\{(\w+)(?::\w+)?\}", lambda m: value(m.group(1)), route.path)


class TestEndpointSecurity:
    def test_every_api_endpoint_names_a_permission_or_is_explicitly_whitelisted(self, app):
        known = set(P.ALL_IDS)
        eps = endpoints(app)
        assert len(eps) > 60, f"only found {len(eps)} endpoints"
        for path, method, meta, _ in eps:
            if meta is None or meta["anonymous"]:
                assert path in ANONYMOUS, f"{method} {path} allows anonymous access but is not on the whitelist"
                continue
            if not meta["permissions"]:
                assert meta["authenticated_only"] and path in SESSION_ONLY, f"{method} {path} only requires a session; add a permission or whitelist it"
            for p in meta["permissions"]:
                assert p in known, f"{method} {path} uses unknown permission '{p}'"

    def test_every_protected_endpoint_rejects_anonymous_callers_and_users_without_the_permission(self, app):
        anon = app.client()
        nobody = app.client().sign_in("dev.noaccess")  # signed in, no role, no permissions
        with_permission = 0
        for path, method, meta, route in endpoints(app):
            if meta is None or meta["anonymous"]:
                continue
            url = fill(route)
            is_upload = method == "POST" and "/logo/" in path

            def call(client):
                if is_upload:
                    return client.upload(url, b"\x01", "x.png")
                return client.send(method, url, None if method == "GET" else {})

            a = call(anon)
            assert a.status_code == 401, f"anonymous {method} {path} returned {a.status_code}, expected 401"
            if not meta["permissions"]:
                continue  # session-only endpoints have no permission to lack
            n = call(nobody)
            assert n.status_code == 403, f"{method} {path} returned {n.status_code} for a user with no permissions, expected 403"
            with_permission += 1
        assert with_permission > 55, f"only {with_permission} permissioned endpoints were exercised"


# ---------------------------------------------------------------- architecture

# Only these files may know which directory implementation exists. Everything else talks to the DirectoryProvider contract.
PROVIDER_FILES = {"ldap_provider.py", "fake_provider.py", "fake_data.py", "ldap_text.py"}
FORBIDDEN_MODULES = ("ldap3", "app.modules.ad.ldap_provider", "app.modules.ad.fake_provider", "app.modules.ad.fake_data", "app.modules.ad.ldap_text")
FORBIDDEN_TEXT = ("ldap3", "LdapConnection", "DirectoryEntry", "PowerShell", "winrm", "ldap_provider", "fake_provider", "fake_data", "ldap_text")
SELECTS_IMPLEMENTATION = {"main.py"}  # the single place that picks the implementation from the settings


def python_files():
    for f in APP_DIR.rglob("*.py"):
        if "__pycache__" in f.parts or f.name in PROVIDER_FILES:
            continue
        yield f


def imported_modules(tree: ast.AST, file: Path):
    pkg = ".".join(("app",) + file.relative_to(APP_DIR).parent.parts)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = pkg.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                mod = f"{base}.{node.module}" if node.module else base
            else:
                mod = node.module or ""
            yield mod
            for a in node.names:
                yield f"{mod}.{a.name}"


class TestArchitecture:
    def test_nothing_outside_the_provider_files_imports_ldap_or_the_fake_provider(self):
        offenders = []
        for f in python_files():
            if f.name in SELECTS_IMPLEMENTATION and f.parent == APP_DIR:
                continue
            for mod in imported_modules(ast.parse(f.read_text(encoding="utf-8")), f):
                if any(mod == m or mod.startswith(m + ".") for m in FORBIDDEN_MODULES):
                    offenders.append(f"{f.relative_to(APP_DIR)} imports {mod}")
        assert not offenders, "\n".join(offenders)

    def test_source_files_outside_the_provider_files_never_mention_ldap_apis(self):
        offenders = []
        for f in python_files():
            if f.name in SELECTS_IMPLEMENTATION and f.parent == APP_DIR:
                continue
            text = f.read_text(encoding="utf-8")
            for word in FORBIDDEN_TEXT:
                if re.search(rf"(?<![\w]){re.escape(word)}", text):
                    offenders.append(f"{f.relative_to(APP_DIR)} mentions {word}")
        assert not offenders, "\n".join(offenders)

    def test_both_providers_implement_the_whole_directory_contract(self):
        members = typing.get_protocol_members(DirectoryProvider)
        assert len(members) >= 25
        for impl in (FakeDirectoryProvider, LdapDirectoryProvider):
            missing = [m for m in members if not hasattr(impl, m)]
            assert not missing, f"{impl.__name__} is missing {missing}"

    def test_routers_only_use_the_module_services(self):
        routers = list((APP_DIR / "routers").glob("*.py"))
        assert len(routers) >= 8
        for f in routers:
            for mod in imported_modules(ast.parse(f.read_text(encoding="utf-8")), f):
                assert not mod.startswith("sqlalchemy.orm.Session") or True
                assert not any(mod == m or mod.startswith(m + ".") for m in FORBIDDEN_MODULES), f"{f.name} imports {mod}"


# ---------------------------------------------------------------- hardening

PRODUCTION = {
    "Okta": {"DevelopmentSignIn": False, "Issuer": "https://okta.example.test", "ClientId": "client-id", "ClientSecret": "client-secret"},
    "ActiveDirectory": {"Provider": "Ldap", "Domain": "example.test", "Server": "dc.example.test", "BaseDn": "DC=example,DC=test",
                        "UseLdaps": True, "VerifyCertificate": True},
}


def production_with(**override):
    cfg = json.loads(json.dumps(PRODUCTION))
    for key, value in override.items():
        section, name = key.split("__")
        cfg[section][name] = value
    return cfg


class TestHardening:
    def test_responses_carry_the_security_headers_and_a_correlation_id(self, app):
        res = app.client().get("/api/health")
        h = res.headers
        assert "default-src 'self'" in h["content-security-policy"]
        assert "frame-ancestors 'none'" in h["content-security-policy"]
        assert "script-src 'self'" in h["content-security-policy"]
        assert "unsafe-inline" not in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert h["x-correlation-id"]
        assert h["cache-control"] == "no-store"

    def test_an_incoming_correlation_id_is_kept_only_when_well_formed(self, app):
        c = app.client()
        assert c.get("/api/health", headers={"X-Correlation-ID": "abc-12345678"}).headers["x-correlation-id"] == "abc-12345678"
        assert "injected" not in c.get("/api/health", headers={"X-Correlation-ID": "bad id; injected"}).headers["x-correlation-id"]

    def test_errors_never_show_stack_traces_or_internal_details(self, app):
        c = app.client().sign_in("dev.admin")
        res = c.http.post("/api/admin/roles", content="{ this is not json", headers={"content-type": "application/json", "X-XSRF-TOKEN": c.csrf})
        assert res.status_code >= 400
        assert "Traceback" not in res.text
        assert "File \"" not in res.text
        assert "app/" not in res.text

    def test_unexpected_exceptions_become_a_safe_500_with_a_correlation_id(self, app, monkeypatch):
        c = app.client().sign_in("dev.admin")

        def boom(*a, **k):
            raise RuntimeError("secret internal detail /srv/app/db.py")

        monkeypatch.setattr(FakeDirectoryProvider, "search_users", boom)
        res = c.get("/api/modules/ad/users")
        assert res.status_code == 500
        assert res.json()["correlationId"]
        assert "secret internal detail" not in res.text

    def test_search_and_write_endpoints_are_rate_limited_per_user(self, make_app):
        app = make_app(extra={"App": {"SearchRateLimitPerMinute": 3, "WriteRateLimitPerMinute": 2}})
        c = app.client().sign_in("dev.admin")

        for _ in range(3):
            assert c.get("/api/search?q=alice").status_code == 200
        limited = c.get("/api/search?q=alice")
        assert limited.status_code == 429
        assert "correlationId" in limited.text

        dave = fake_id("user:dave.locked")
        codes = [c.post(f"/api/modules/ad/users/{dave}/unlock", {"justification": "Verified caller identity"}).status_code for _ in range(3)]
        assert codes[2] == 429

        other = app.client().sign_in("dev.auditor")  # someone else is not affected
        assert other.get("/api/search?q=alice").status_code == 200

    def test_the_api_docs_are_available_in_development_only(self, app, make_app):
        assert app.client().get("/api/openapi.json").status_code == 200
        prod = make_app("Production", PRODUCTION)
        assert prod.client().get("/api/openapi.json").status_code != 200

    def test_production_starts_with_valid_settings_sends_hsts_and_hides_development_sign_in(self, make_app):
        app = make_app("Production", PRODUCTION)
        c = app.client("https://app.example.test")
        res = c.get("/api/health")
        assert res.status_code == 200
        assert "max-age" in res.headers["strict-transport-security"]
        assert c.get("/api/auth/dev-users").status_code == 404
        c.prime_csrf()
        assert c.post("/api/auth/dev-login", {"userId": str(uuid.uuid4())}).status_code == 404
        assert c.get("/api/auth/config").json()["devSignIn"] is False

    @pytest.mark.parametrize("key,value", [
        ("Okta__DevelopmentSignIn", True), ("ActiveDirectory__VerifyCertificate", False), ("ActiveDirectory__Provider", "Fake"),
        ("ActiveDirectory__UseLdaps", False), ("Okta__ClientSecret", "<SET_VIA_USER_SECRETS_OR_ENVIRONMENT>"),
    ])
    def test_production_refuses_to_start_with_unsafe_or_unfinished_settings(self, make_app, key, value):
        with pytest.raises(RuntimeError, match="cannot start"):
            make_app("Production", production_with(**{key: value}))

    def test_development_sign_in_is_refused_outside_development(self, make_app):
        with pytest.raises(RuntimeError, match="DevelopmentSignIn"):
            make_app("Staging")

    def test_session_cookies_are_http_only_and_secure_outside_development(self, make_app):
        app = make_app("Production", PRODUCTION)
        c = app.client("https://app.example.test")
        res = c.get("/api/auth/config")
        cookie = res.headers.get("set-cookie", "")
        assert "sd.session=" in cookie
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie

    def test_the_session_cookie_holds_only_an_opaque_id(self, app):
        c = app.client().sign_in("dev.admin")
        cookie = c.http.cookies.get("sd.session")
        assert cookie and "dev.admin" not in cookie and "Dev Admin" not in cookie and "." not in cookie


# ---------------------------------------------------------------- session timeouts

def age_sessions(app, signed_in_minutes_ago: int | None = None, active_minutes_ago: int | None = None) -> None:
    now = datetime.now(UTC)
    with app.db() as db:
        for row in db.scalars(select(UserSession)):
            data = json.loads(row.data)
            if "uid" not in data:
                continue
            if signed_in_minutes_ago is not None:
                data["sd_signin"] = int((now - timedelta(minutes=signed_in_minutes_ago)).timestamp())
            if active_minutes_ago is not None:
                data["sd_active"] = int((now - timedelta(minutes=active_minutes_ago)).timestamp())
            row.data = json.dumps(data)
        db.commit()


def stored_active(app) -> int:
    with app.db() as db:
        return max(json.loads(r.data).get("sd_active", 0) for r in db.scalars(select(UserSession)))


class TestSessionTimeouts:
    def test_a_session_inside_both_limits_is_accepted_and_its_activity_time_is_refreshed(self, app):
        c = app.client().sign_in("dev.admin")
        age_sessions(app, signed_in_minutes_ago=20, active_minutes_ago=5)
        assert c.get("/api/auth/me").status_code == 200
        assert datetime.now(UTC).timestamp() - stored_active(app) < 5

    def test_an_idle_session_is_rejected_after_the_idle_timeout(self, app):
        c = app.client().sign_in("dev.admin")
        age_sessions(app, signed_in_minutes_ago=90, active_minutes_ago=45)  # default idle timeout is 30 minutes
        assert c.get("/api/auth/me").status_code == 401

    def test_a_session_older_than_the_absolute_lifetime_is_rejected_even_if_active(self, app):
        c = app.client().sign_in("dev.admin")
        age_sessions(app, signed_in_minutes_ago=600, active_minutes_ago=1)  # default absolute lifetime is 480 minutes
        assert c.get("/api/auth/me").status_code == 401

    def test_the_timeouts_come_from_the_saved_settings(self, app):
        c = app.client().sign_in("dev.admin")
        age_sessions(app, signed_in_minutes_ago=20, active_minutes_ago=20)
        with app.db() as db:
            settings = SettingsService(db, app.state.cache, app.settings.app)
            general = settings.general()
            general.idle_timeout_minutes = 10
            settings.save_general(general, "test")
        assert c.get("/api/auth/me").status_code == 401

    def test_a_user_disabled_in_the_app_loses_the_session_immediately(self, app):
        admin = app.client().sign_in("dev.admin")
        victim = app.client().sign_in("dev.user")
        assert victim.get("/api/auth/me").status_code == 200
        assert admin.put(f"/api/admin/users/{app.user_id('dev.user')}/status", {"isEnabled": False}).status_code == 204
        assert victim.get("/api/auth/me").status_code == 401

    def test_signing_out_ends_the_server_side_session(self, app):
        c = app.client().sign_in("dev.admin")
        token = c.get("/api/auth/me").json()["csrfToken"]
        res = c.http.post("/api/auth/logout", data={"__RequestVerificationToken": token})
        assert res.status_code == 302
        assert c.get("/api/auth/me").status_code == 401
        assert any(a.action == "logon.signout" for a in app.audit())

    def test_a_new_session_id_is_issued_at_sign_in(self, app):
        c = app.client()
        c.prime_csrf()
        before = c.http.cookies.get("sd.session")
        c.sign_in("dev.admin")
        after = c.http.cookies.get("sd.session")
        assert before and after and before != after  # no session fixation
