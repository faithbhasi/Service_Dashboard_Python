"""The Okta sign-in (authorization code with PKCE) exercised against a local OpenID Connect provider."""
import os
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app import permissions as P
from app.db import AuditResult
from tests.fake_idp import FakeIdp

os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "1")  # the test IdP is plain http on localhost


@pytest.fixture
def idp():
    i = FakeIdp().start()
    yield i
    i.stop()


@pytest.fixture
def okta_app(make_app, idp):
    return make_app(extra={"Okta": {"DevelopmentSignIn": False, "Issuer": idp.issuer, "ClientId": idp.client_id, "ClientSecret": idp.client_secret}})


def go_through_idp(client, return_url: str | None = None):
    """Browser flow: /api/auth/login -> IdP authorize -> back to /signin-oidc. Returns (login response, callback response)."""
    login = client.get("/api/auth/login" + (f"?returnUrl={return_url}" if return_url else ""))
    assert login.status_code == 302
    assert login.headers["location"].startswith("http://127.0.0.1")
    at_idp = httpx.get(login.headers["location"], follow_redirects=False)
    assert at_idp.status_code == 302
    back = urlsplit(at_idp.headers["location"])
    callback = client.get(f"{back.path}?{back.query}")
    return login, callback


def test_login_redirects_to_okta_with_pkce_state_nonce_and_the_configured_scopes(okta_app, idp):
    c = okta_app.client()
    login = c.get("/api/auth/login")
    q = parse_qs(urlsplit(login.headers["location"]).query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == [idp.client_id]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"][0] and q["state"][0] and q["nonce"][0]
    assert q["redirect_uri"] == ["http://localhost/signin-oidc"]
    assert set(q["scope"][0].split()) >= {"openid", "profile", "email", "groups"}
    assert "client_secret" not in login.headers["location"]


def test_a_successful_sign_in_provisions_the_user_applies_group_mappings_and_audits(okta_app, idp):
    admin = okta_app.client().sign_in  # (dev sign-in is off here: create the mapping directly in the database instead)
    del admin
    from app.db import GroupMapping

    with okta_app.db() as db:
        db.add(GroupMapping(okta_group="IT-Admins", role_id=str(P.ADMINS_ID)))
        db.commit()
    idp.claims = {"sub": "okta|alice", "email": "alice@example.test", "name": "Alice Okta", "groups": ["IT-Admins", "Everyone"]}

    c = okta_app.client()
    _, callback = go_through_idp(c, return_url="/ad/users")
    assert callback.status_code == 302
    assert callback.headers["location"] == "/ad/users"

    me = c.get("/api/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["displayName"] == "Alice Okta"
    assert body["email"] == "alice@example.test"
    assert body["hasAccess"] is True
    assert any(r["name"] == "Admins" for r in body["roles"])
    assert len(body["permissions"]) == len(P.ALL)

    assert idp.token_requests and idp.token_requests[-1]["has_verifier"]  # PKCE verifier was sent
    assert any(a.action == "logon.signin" and a.result == AuditResult.SUCCESS for a in okta_app.audit())
    # Only the ID token is kept (to sign out of Okta); the opaque access token is never stored.
    with okta_app.db() as db:
        from app.db import UserSession

        assert "opaque-access-token" not in " ".join(s.data for s in db.query(UserSession))


def test_a_user_in_no_mapped_group_signs_in_without_access(okta_app, idp):
    idp.claims = {"sub": "okta|bob", "email": "bob@example.test", "name": "Bob Okta", "groups": ["Everyone"]}
    c = okta_app.client()
    _, callback = go_through_idp(c)
    assert callback.status_code == 302
    assert c.get("/api/auth/me").json()["hasAccess"] is False


def test_a_forged_state_or_missing_code_is_rejected_and_audited(okta_app, idp):
    c = okta_app.client()
    login = c.get("/api/auth/login")
    assert login.status_code == 302
    forged = c.get("/signin-oidc?code=abc&state=forged-state")
    assert forged.status_code == 302
    assert forged.headers["location"] == "/login?error=failed"
    assert c.get("/api/auth/me").status_code == 401
    assert any(a.action == "logon.failed" and a.result == AuditResult.FAILURE for a in okta_app.audit())
    assert c.get("/signin-oidc").headers["location"] == "/login?error=failed"


def test_an_id_token_with_the_wrong_nonce_or_signature_is_rejected(okta_app, idp):
    c = okta_app.client()
    login = c.get("/api/auth/login")
    at_idp = httpx.get(login.headers["location"], follow_redirects=False)
    # Break the nonce the IdP will put into the ID token.
    for data in idp.codes.values():
        data["nonce"] = "not-the-nonce"
    back = urlsplit(at_idp.headers["location"])
    assert c.get(f"{back.path}?{back.query}").headers["location"] == "/login?error=failed"
    assert c.get("/api/auth/me").status_code == 401


def test_open_redirects_through_return_url_are_refused(okta_app, idp):
    for bad in ("//evil.example", "https://evil.example", "/\\evil.example"):
        c = okta_app.client()
        _, callback = go_through_idp(c, return_url=bad.replace("\\", "%5C"))
        assert callback.headers["location"] == "/"


def test_sign_out_clears_the_session_and_goes_to_okta_with_the_id_token_hint(okta_app, idp):
    c = okta_app.client()
    go_through_idp(c)
    token = c.get("/api/auth/me").json()["csrfToken"]
    out = c.http.post("/api/auth/logout", data={"__RequestVerificationToken": token})
    assert out.status_code == 302
    loc = out.headers["location"]
    assert loc.startswith(idp.issuer + "/logout")
    q = parse_qs(urlsplit(loc).query)
    assert q["id_token_hint"][0].count(".") == 2
    assert q["post_logout_redirect_uri"] == ["http://localhost/signout-callback-oidc"]
    assert c.get("/api/auth/me").status_code == 401


def test_sign_out_without_the_antiforgery_token_is_refused(okta_app, idp):
    c = okta_app.client()
    go_through_idp(c)
    assert c.http.post("/api/auth/logout", data={}).status_code == 400
    assert c.get("/api/auth/me").status_code == 200
