"""A tiny OpenID Connect provider (authorization code + PKCE) for testing the Okta sign-in against a real HTTP round trip."""
from __future__ import annotations

import base64
import hashlib
import socket
import threading
import time
import uuid
from urllib.parse import urlencode

import uvicorn
from authlib.jose import JsonWebKey, jwt
from fastapi import FastAPI, Form, Request
from starlette.responses import JSONResponse, RedirectResponse


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeIdp:
    def __init__(self, client_id: str = "test-client", client_secret: str = "test-secret"):
        self.port = free_port()
        self.issuer = f"http://127.0.0.1:{self.port}"
        self.client_id, self.client_secret = client_id, client_secret
        self.key = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "k1"})
        self.claims: dict = {"sub": "okta|alice", "email": "alice@example.test", "name": "Alice Okta", "groups": []}
        self.codes: dict[str, dict] = {}
        self.token_requests: list[dict] = []
        self.app = self._build()
        self._server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error"))
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def _build(self) -> FastAPI:
        app = FastAPI()
        idp = self

        @app.get("/.well-known/openid-configuration")
        def meta():
            return {"issuer": idp.issuer, "authorization_endpoint": idp.issuer + "/authorize", "token_endpoint": idp.issuer + "/token",
                    "jwks_uri": idp.issuer + "/keys", "end_session_endpoint": idp.issuer + "/logout", "response_types_supported": ["code"],
                    "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]}

        @app.get("/keys")
        def keys():
            return {"keys": [idp.key.as_dict(is_private=False)]}

        @app.get("/authorize")
        def authorize(request: Request):
            q = dict(request.query_params)
            code = uuid.uuid4().hex
            idp.codes[code] = {"nonce": q.get("nonce"), "challenge": q.get("code_challenge"), "method": q.get("code_challenge_method"),
                               "redirect_uri": q["redirect_uri"], "client_id": q.get("client_id"), "scope": q.get("scope", "")}
            return RedirectResponse(q["redirect_uri"] + "?" + urlencode({"code": code, "state": q["state"]}), status_code=302)

        @app.post("/token")
        async def token(request: Request, code: str = Form(), code_verifier: str = Form(default=""), redirect_uri: str = Form(default=""),
                        grant_type: str = Form(default="")):
            idp.token_requests.append({"code": code, "has_verifier": bool(code_verifier), "auth": request.headers.get("authorization", "")})
            data = idp.codes.pop(code, None)
            if data is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if data["method"] == "S256":
                digest = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
                if digest != data["challenge"]:
                    return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)
            now = int(time.time())
            claims = {"iss": idp.issuer, "aud": idp.client_id, "iat": now, "exp": now + 300, "nonce": data["nonce"], **idp.claims}
            id_token = jwt.encode({"alg": "RS256", "kid": "k1"}, claims, idp.key).decode()
            return {"access_token": "opaque-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": id_token}

        return app

    def start(self) -> FakeIdp:
        self._thread.start()
        for _ in range(100):
            if self._server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("fake IdP did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)
