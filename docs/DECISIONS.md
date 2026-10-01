# Decisions and known limitations (Python edition)

This is a port of the ASP.NET Core edition to **Python 3.13**. The JSON API, the database model, the permissions, the audit trail, the
safety rules and the React front end are the same, so behaviour is the same. Where Python or its libraries differ, the choice is recorded here.

## 1. What is deliberately the same

* The HTTP API: routes, JSON field names (camelCase), status codes, problem-details errors with `code` and `correlationId`, the `X-XSRF-TOKEN` header.
* Permissions, default roles (Admins, Auditors and Security, Users), role AD scope, escalation guards and last-administrator safeguards.
* The AD change pipeline order: permission, Action Policy input checks, fresh re-read, typed confirmation, allowlists / protected objects / role scope,
  dry run, change, audit. A "Validate" records one `Validated (no change made)` row; the automatic dry run inside a real change records none.
* The Fake directory (same seed data and the same object GUIDs: `uuid.UUID(bytes_le=md5(...))` reproduces .NET's `new Guid(bytes)`).
* The audit table is append-only (SQLite trigger); retention is a separate, audited delete.

## 2. Where this edition differs

| Area | .NET edition | Python edition | Why |
| --- | --- | --- | --- |
| Sessions | Encrypted auth cookie holding claims | **Server-side session** in SQLite; the cookie (`sd.session`, HttpOnly, SameSite=Lax, Secure outside Development) is an opaque random id; the id is rotated at sign-in | Nothing sensitive is ever in the browser, and a session can be revoked on the server |
| Anti-forgery | Framework antiforgery cookie + header | Random token stored in the session, sent in `X-XSRF-TOKEN` (or the logout form field), compared in constant time | Same effect with fewer parts |
| Okta | ASP.NET OIDC handler | **Authlib**: authorization code + PKCE (S256), `response_mode=query`; only the ID token is kept | Standard for Python |
| LDAP | System.DirectoryServices.Protocols | **ldap3** | Cross-platform |
| Large result paging | Server-side sort + virtual list view | **No VLV in ldap3**: results are scanned up to the search limit (default 1000, max 5000) and paged in the application. Group member lists scan up to 100,000 members | A known cost on very large groups |
| Integrated bind | Negotiate as the process identity (gMSA) | GSSAPI/Kerberos through the optional `gssapi` / `winkerberos` package, or a simple bind with a test account (Development only) | Python has no built-in SSPI |
| Rate limiting | ASP.NET rate limiter | A fixed one-minute window per user (or per IP when anonymous), in process | Same behaviour; **run one worker** |
| Passwords in memory | `SecureString` | A Python `str` (immutable; cannot be wiped). It is taken out of the request object at once, never logged, audited or returned, and is not sent at all in a dry run | Python has no equivalent; the exposure is the process memory only |
| API description | OpenAPI JSON at `/openapi/v1.json` | FastAPI's OpenAPI at `/api/openapi.json` and docs at `/api/docs`, Development only | Built in |
| Front end build | `src/Frontend` to `wwwroot` | `frontend/` to `app/static` | Same sources |

## 3. Limitations you should know about

1. **The LDAP provider has not been run against a real domain controller** in this repository's tests (there is none available). Everything above it
   (the change pipeline, protections, scope, audit) is tested with the Fake provider, and the LDAP filter builders and DN/SID helpers have their own unit
   tests. Run **Settings > AD Integration > Test connection** and every action's **Validate** against a test domain before real use
   ([CONNECT-REAL-AD-AND-OKTA.md](CONNECT-REAL-AD-AND-OKTA.md)).
2. **Integrated Kerberos bind** (no stored password) is the least-tested path: it needs the right Kerberos packages and ticket or keytab on the host.
3. **HasChildren in the OU tree** is assumed true on a real directory (finding out would cost one query per OU); expanding an empty OU shows nothing.
4. The Okta sign-in is tested against a local OpenID Connect provider (redirect, PKCE, token validation, nonce and state, group mapping, sign-out), not
   against Okta itself.
5. SQLite only, one process, one worker. Scaling out needs a shared session, settings and rate-limit store.

## 4. Found while porting

Writing the tests against the real application found two defects in the new code, both fixed and now covered:

* A first-time Okta user was treated as disabled (a column default is applied only when a row is saved). Covered by `tests/test_oidc.py`.
* The log redaction missed a secret inside a dictionary that was formatted into the message (`{'newPassword': '...'}`). Covered by `tests/test_foundation.py`.

## 5. Choices carried over

* One provider per directory type, selected by one setting; nothing outside the provider files knows which one is in use (enforced by a test).
* Every AD action uses LDAP over LDAPS; nothing needs PowerShell or RSAT.
* The allowlists, protected lists and attribute names live in the `ad` settings document (SQLite), audited on every change.
* Time is UTC in the database and the API, shown in the configured time zone in the UI.
* The first administrator comes from `App:BootstrapAdminOktaGroup` when nothing is mapped to Admins yet.
