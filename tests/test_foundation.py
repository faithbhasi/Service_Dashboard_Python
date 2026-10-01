import logging

import pytest
from sqlalchemy import select

from app import permissions as P
from app.config import load_settings, validate_startup
from app.db import AuditLog, AuditResult
from app.logging_setup import SensitiveDataFilter, get_logger


def validate(tmp_path, values: dict, environment: str) -> list[str]:
    return validate_startup(load_settings(environment, values, root=tmp_path))


class TestStartupValidation:
    def test_development_sign_in_outside_development_is_refused(self, tmp_path):
        errors = validate(tmp_path, {"Okta": {"DevelopmentSignIn": "true"}, "ActiveDirectory": {"Provider": "Fake"}}, "Staging")
        assert any("DevelopmentSignIn" in e for e in errors)

    def test_development_sign_in_in_development_is_allowed(self, tmp_path):
        assert validate(tmp_path, {"Okta": {"DevelopmentSignIn": "true"}, "ActiveDirectory": {"Provider": "Fake"}}, "Development") == []

    def test_production_refuses_disabled_certificate_checks_and_plain_ldap(self, tmp_path):
        errors = validate(tmp_path, {
            "ActiveDirectory": {"Provider": "Ldap", "VerifyCertificate": "false", "UseLdaps": "false", "Domain": "example.test",
                                "Server": "dc.example.test", "BaseDn": "DC=example,DC=test"},
            "Okta": {"Issuer": "https://x", "ClientId": "x", "ClientSecret": "x"},
            "App": {"DataDirectory": "d", "AssetDirectory": "a"}, "Serilog": {"LogDirectory": "l"},
        }, "Production")
        assert any("VerifyCertificate" in e for e in errors)
        assert any("UseLdaps" in e for e in errors)

    def test_local_test_bind_credentials_are_refused_outside_development(self, tmp_path):
        values = {"ActiveDirectory": {"Provider": "Fake", "BindUsername": "svc@example.test"}}
        assert any("BindUsername" in e for e in validate(tmp_path, values, "Staging"))
        assert any("BindUsername" in e for e in validate(tmp_path, values, "Production"))
        assert not any("BindUsername" in e for e in validate(tmp_path, values, "Development"))

    def test_production_refuses_unfilled_placeholders_and_the_fake_provider(self, tmp_path):
        errors = validate(tmp_path, {
            "ActiveDirectory": {"Provider": "Fake"},
            "Okta": {"Issuer": "<OKTA_ISSUER_URL>", "ClientId": "<OKTA_CLIENT_ID>", "ClientSecret": "<SET_VIA_USER_SECRETS_OR_ENVIRONMENT>"},
            "App": {"DataDirectory": "<DATA_DIRECTORY>"},
        }, "Production")
        assert any("Fake" in e for e in errors)
        assert any("Okta:Issuer" in e for e in errors)
        assert any("App:DataDirectory" in e for e in errors)


class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []
        self.addFilter(SensitiveDataFilter())

    def emit(self, record):
        self.lines.append(record.getMessage() + " | " + str({k: v for k, v in record.__dict__.items() if k in ("request", "body", "access_token")}))


@pytest.fixture
def sink():
    log = logging.getLogger("sd.redaction-test")
    log.setLevel(logging.INFO)
    log.propagate = False
    h = ListHandler()
    log.addHandler(h)
    yield log, h
    log.removeHandler(h)


class TestLogRedaction:
    def test_password_properties_are_redacted_even_when_nested(self, sink):
        log, h = sink
        log.info("Reset requested %s with password=%s", {"userName": "alice", "newPassword": "Sup3r-Secret!"}, "Sup3r-Secret!",
                 extra={"request": {"userName": "alice", "newPassword": "Sup3r-Secret!"}})
        log.info("Token is %s", "access_token=abc.def.ghi", extra={"access_token": "abc.def.ghi"})
        everything = "\n".join(h.lines)
        assert "Sup3r-Secret!" not in everything
        assert "abc.def.ghi" not in everything
        assert "alice" in everything

    def test_password_text_inside_a_string_value_is_redacted(self, sink):
        log, h = sink
        log.info("Payload %s", '{"user":"a"} password=Hunter2!! trailing')
        assert "Hunter2!!" not in "\n".join(h.lines)


class TestSignIn:
    def test_anonymous_requests_to_protected_endpoints_get_401_problem_details_with_a_correlation_id(self, app):
        c = app.client()
        res = c.get("/api/auth/me")
        assert res.status_code == 401
        assert res.headers["X-Correlation-ID"]
        assert "problem+json" in res.headers["content-type"]
        assert res.json()["correlationId"]

    def test_admin_can_sign_in_and_sees_every_permission(self, app):
        c = app.client().sign_in("dev.admin")
        me = c.get("/api/auth/me").json()
        assert me["hasAccess"] is True
        assert len(me["permissions"]) == len(P.ALL)

    def test_user_without_a_role_signs_in_but_has_no_access(self, app):
        c = app.client().sign_in("dev.noaccess")
        me = c.get("/api/auth/me").json()
        assert me["hasAccess"] is False
        assert len(me["permissions"]) == 0

    def test_user_disabled_in_the_app_is_denied_and_the_attempt_is_audited(self, app):
        c = app.client().sign_in("dev.disabled")
        assert c.last_sign_in.status_code == 403
        assert c.get("/api/auth/me").status_code == 401
        assert any(a.action == "logon.denied" and a.result == AuditResult.DENIED for a in app.audit())

    def test_state_changing_requests_without_an_antiforgery_token_are_rejected(self, app):
        c = app.client().sign_in("dev.admin")
        res = c.http.put("/api/auth/preferences", json={"theme": "dark", "navCollapsed": False})
        assert res.status_code == 400

    def test_sign_in_and_page_access_are_audited(self, app):
        c = app.client().sign_in("dev.helpdesk")
        assert c.post("/api/auth/access", {"page": "ad.users"}).json()["allowed"] is True
        assert c.post("/api/auth/access", {"page": "settings"}).json()["allowed"] is False
        rows = app.audit()
        assert any(a.action == "logon.signin" for a in rows)
        assert any(a.action == "page.view" and a.target == "settings" and a.result == AuditResult.DENIED for a in rows)

    def test_audit_rows_cannot_be_updated(self, app):
        app.client().sign_in("dev.admin")
        with app.db() as db:
            row = db.scalars(select(AuditLog)).first()
            row.error = "tampered"
            with pytest.raises(Exception):
                db.commit()
