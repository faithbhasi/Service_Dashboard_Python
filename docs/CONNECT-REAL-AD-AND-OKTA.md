# Connecting a real (test) Active Directory and Okta on your own machine

Local development normally uses the Fake directory and a "pick a test user" sign-in. These two switches are independent, so do it in two
stages and check each one before adding the next:

* **Part A**: real AD, still signing in with the development picker.
* **Part B**: Okta sign-in as well.

Local overrides go in **`config/settings.local.json`** (git-ignored) or in environment variables. They override `settings.development.json`.
To go back to the Fake directory, delete `config/settings.local.json`.

```json
{
  "ActiveDirectory": { "Provider": "Ldap" }
}
```

Environment variables use `SD__Section__Key`. PowerShell: `$env:SD__ActiveDirectory__Provider = "Ldap"`; bash: `export SD__ActiveDirectory__Provider=Ldap`.

## Part A: Active Directory

### A1. What the test domain needs

1. A domain controller reachable from your machine: `Test-NetConnection <DC_FQDN> -Port 636` must say `TcpTestSucceeded : True`.
2. **LDAPS on the DC** (port 636 with a certificate). Passwords can only be set over an encrypted connection.
3. Your machine must **trust the certificate's issuer** (import the CA certificate into *Trusted Root Certification Authorities*;
   on Linux add it to the system store or set `SSL_CERT_FILE`). Lab shortcut, Development only: `VerifyCertificate` = `false`.
   The application refuses that in Production.
4. A few **test OUs and objects** so nothing important is touched, for example `OU=ITDash-Test,DC=corp,DC=test` with child OUs
   `Users`, `Computers`, `Groups`, some test users, a test computer and test groups.
5. A **service account** for the app to bind as (for example `svc-itdash-test`) with the rights from [AD-DELEGATION.md](AD-DELEGATION.md)
   section 3 on the test OUs only. Do not use a Domain Admin, even in a lab.

### A2. Find your values

| You need | Example | How to find it |
| --- | --- | --- |
| `<AD_DOMAIN_FQDN>` | `corp.test` | `(Get-ADDomain).DNSRoot` |
| `<DC_FQDN>` | `dc01.corp.test` | `(Get-ADDomainController).HostName` |
| `<AD_BASE_DN>` | `DC=corp,DC=test` | `(Get-ADDomain).DistinguishedName` |

### A3. Write `config/settings.local.json`

```json
{
  "ActiveDirectory": {
    "Provider": "Ldap",
    "Domain": "corp.test",
    "Server": "dc01.corp.test",
    "Port": 636,
    "UseLdaps": true,
    "BaseDn": "DC=corp,DC=test",
    "BindUsername": "svc-itdash-test@corp.test",
    "BindPassword": "<PASSWORD>",
    "VerifyCertificate": false
  }
}
```

(`VerifyCertificate: false` only if your machine does not trust the DC certificate yet.)

`BindUsername` / `BindPassword` exist for **local testing only**: the application refuses to start outside Development if they are set.
With a user name the application does a simple bind over LDAPS. Without one it uses **integrated Kerberos (GSSAPI)** as the identity the
process runs as, which needs an extra package: `pip install gssapi` (Linux, with a Kerberos ticket or keytab) or `pip install winkerberos`
(Windows, domain-joined). If you do not need integrated sign-in, use the bind account for local testing.

### A4. Run and check

1. Start the application (`scripts/run-dev.ps1` or `run-dev.sh`) and sign in as **Dev Admin**.
2. **Settings > AD Integration**: the connection card should say provider **Ldap**. Press **Test connection**: Bind, Search base,
   Secure connection and Sample search should all pass. Failures name the step.
3. The allowlists start **empty on a real directory** (nothing is manageable). Still in AD Integration add your test users OU under
   *Manageable OUs - users* (use **Browse OUs**), the computers OU under *computers*, search for your test groups under *Manageable groups*, then Save.
4. Open **Active Directory > Users**, search for a test user and open it. Press **Validate** on Password reset, Unlock, Enable/Disable, Groups and Move OU:
   it reads `allowedAttributesEffective` from AD and names any delegated right that is missing, without changing anything.
5. Then do one real change on a test account and look at **Activity and Logs > Admin Actions**.

### A5. Typical problems

| Symptom | Cause / fix |
| --- | --- |
| Test connection: Bind fails | Wrong user name or password. Use the UPN (`user@corp.test`) |
| "Directory unavailable" / connection errors | DC name not resolvable, port 636 closed, or the certificate does not match `ActiveDirectory:Server` (use the DC's FQDN, not an IP) |
| Certificate / SSL error | Trust the CA (A1.3) or use `VerifyCertificate=false` in Development |
| Search returns nothing | `BaseDn` wrong, or the service account cannot read the OU |
| "The service account does not have permission" | The missing right is named in the dry run; delegate it ([AD-DELEGATION.md](AD-DELEGATION.md)) |
| Reset password: "The domain rejected the password" | AD's own policy (length, complexity, history, minimum age) |
| Large groups are slow to list | ldap3 has no server-side virtual list view, so member lists are read in full (up to 100,000) and paged in the application |

## Part B: Okta

### B1. In Okta

1. **Groups**: create a group for administrators, for example `ITDash-Admins`, and add yourself.
2. **Applications > Create App Integration > OIDC > Web Application**, grant type *Authorization Code*.
   * **Sign-in redirect URI**: `http://localhost:8000/signin-oidc`
   * **Sign-out redirect URI**: `http://localhost:8000/signout-callback-oidc`
   * (If you use the Vite dev server on 5173 instead, register `http://localhost:5173/...`; Vite forwards those two paths to the back end.)
   * Assign the app to the groups that should sign in.
3. Copy the **Client ID** and **Client secret**.
4. **Security > API > Authorization Servers > default**: make sure a `groups` scope exists, and add a claim named `groups`, included in the
   **ID Token (Always)**, value type **Groups**, with a filter such as *Starts with* `ITDash`. Note the **Issuer URI**, for example
   `https://<OKTA_DOMAIN>/oauth2/default`.

More detail in [OKTA-SETUP.md](OKTA-SETUP.md).

### B2. Add to `config/settings.local.json`

```json
{
  "App": { "BootstrapAdminOktaGroup": "ITDash-Admins" },
  "Okta": {
    "DevelopmentSignIn": false,
    "Issuer": "https://<OKTA_DOMAIN>/oauth2/default",
    "ClientId": "<OKTA_CLIENT_ID>",
    "ClientSecret": "<OKTA_CLIENT_SECRET>",
    "GroupsClaim": "groups"
  }
}
```

`BootstrapAdminOktaGroup` is the first-administrator switch: on startup, if nothing is mapped to the Admins role yet, that Okta group is mapped to it.
**Restart** the application after changing settings.

### B3. Sign in

1. Open **http://localhost:8000** (the host and port must match the redirect URI you registered).
2. The login page shows **Sign in with Okta**. After Okta you come back signed in; members of `ITDash-Admins` get the Admins role.
3. Everyone else lands on **No access assigned** until you give them a role: **Users and Groups > Group Mappings** or **App Users**.

The development users stay in the local database but can no longer sign in. To start clean, stop the application and delete the `data/` folder
(this also resets the allowlists and other settings).

### B4. Typical problems

| Symptom | Cause / fix |
| --- | --- |
| Okta error: `redirect_uri` mismatch | The URI in Okta must be exactly the one the app sends, for example `http://localhost:8000/signin-oidc` |
| Back at the login page with "Sign-in could not be completed" | See the **Logons** tab or the console; usually a wrong client secret or issuer |
| Loops back to login | Use one host consistently (`localhost`, not `127.0.0.1`) and clear cookies for it |
| Signed in but **No access assigned** | The `groups` claim is missing from the ID token, or your group does not match `BootstrapAdminOktaGroup` (case-insensitive). Use Okta's *Token Preview* |

## Going back

Delete `config/settings.local.json` and unset any `SD__*` variables: you are back to the Fake directory with the development sign-in.
