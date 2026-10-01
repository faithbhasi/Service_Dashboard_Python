# Okta setup

The application signs users in with **OpenID Connect, Authorization Code flow with PKCE** (Authlib). It keeps only the **ID token**, in the
server-side session, so sign-out can end the Okta session. Access and refresh tokens are discarded.

## 1. Create the application in Okta

**Applications > Create App Integration > OIDC - OpenID Connect > Web Application**

| Setting | Value |
| --- | --- |
| Grant type | Authorization Code |
| Sign-in redirect URI | `https://<APP_HOST>/signin-oidc` |
| Sign-out redirect URI | `https://<APP_HOST>/signout-callback-oidc` |
| Assignments | The groups that should be able to sign in |

For local testing use `http://localhost:8000/signin-oidc` and `http://localhost:8000/signout-callback-oidc` (see
[CONNECT-REAL-AD-AND-OKTA.md](CONNECT-REAL-AD-AND-OKTA.md)). The URI must match exactly: scheme, host, port, no trailing slash.

## 2. Send group names in the ID token

The application maps Okta groups to roles, so the ID token must carry them.

1. **Security > API > Authorization Servers > default > Scopes**: ensure a `groups` scope exists.
2. **Claims > Add Claim**: name `groups`, include in **ID Token** (Always), value type **Groups**, a filter such as *Starts with* `ITDash`, scope `groups`.
3. Use **Token Preview** to confirm the claim appears for a test user.

## 3. Application settings

`config/settings.local.json` or environment variables (`SD__Okta__...`):

| Setting | Value |
| --- | --- |
| `Okta:Issuer` | `https://<OKTA_DOMAIN>/oauth2/default` (the authorization server that issues the `groups` claim) |
| `Okta:ClientId` | the application's client id |
| `Okta:ClientSecret` | the client secret: **environment variable or the git-ignored local file only** |
| `Okta:GroupsClaim` | `groups` |
| `Okta:DevelopmentSignIn` | `false` (the application refuses `true` outside Development) |
| `App:BootstrapAdminOktaGroup` | the Okta group whose members become Admins on first start |

The content-security policy allows forms to post to the issuer's origin so the sign-out redirect works.

## 4. First sign-in

Members of the bootstrap group get the Admins role. Everybody else signs in with **no access** until an administrator maps an Okta group to a role
(**Users and Groups > Group Mappings**) or assigns a role directly (**App Users**). The groups used are the ones saved at the person's last sign-in.

## 5. Secret rotation

Create a new client secret in Okta, update `SD__Okta__ClientSecret` (or the local file), restart the service, then deactivate the old secret.
