# Adding a module (Microsoft 365, Mimecast, Citrix, Okta...)

A module is **a package plus a router**. There is no plugin framework. The core application does not change, beyond mounting the router,
registering the module, adding its permissions and adding its navigation entry. The Active Directory module (`app/modules/ad/` and
`app/routers/ad.py`) is the worked example; this guide uses **M365** (`m365`) as the placeholder.

## 1. Pick the module id

Short, lowercase and fixed once released: `m365`, `mimecast`, `citrix`, `okta`. It becomes the route prefix (`/api/modules/m365`), the key of the
enabled/disabled setting and the audit `module` value.

## 2. Create the package

```
app/modules/m365/
  provider.py          the contract (a typing.Protocol) the rest of the module talks to, plus its data types
  fake_provider.py     an in-memory version for development and tests
  graph_provider.py    the real client (the only file that imports the vendor SDK or HTTP client)
  services.py          the module's logic and its search / dashboard hooks
app/routers/m365.py    routes under /api/modules/m365
```

Keep the same rule as AD: **routers and services never import the vendor client or a concrete provider**. They depend on the `Protocol`.
`tests/test_security.py::TestArchitecture` shows how to extend the "no provider imports outside the provider files" check to a new module.

## 3. Register it

1. Add a `ModuleDescriptor("m365", "Microsoft 365", "Licences and mailboxes.")` to the `modules` list in `app/main.py` and remove the
   `m365` entry from `COMING_SOON` in `app/module_catalog.py` (that is what shows it as "Coming Soon" today).
2. Add the router to `ALL_ROUTERS` in `app/routers/__init__.py` (the endpoint-authorization test walks this list).
3. Optional: global search results and Home cards. Add an object with `module_id`, `search(ctx, query, user)` and
   `dashboard_cards(ctx, user)` to `AppState.hooks` (see `AdHooks` in `app/modules/ad/services.py`).

## 4. Permissions

Add the permission ids and their descriptions in `app/permissions.py` (`ALL`), and give them to the default roles that should have them.
Permission ids follow `module.area.action`, for example `m365.licences.assign`.

## 5. Endpoints

Every route names its permission through the `guard` dependency, and the module gate, so a disabled module answers with a 403 `module_disabled`:

```python
@router.get("/licences")
def licences(ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.M365_LICENCES_READ, module="m365", rate="search"))):
    ...
```

State-changing endpoints use `rate="write"`; the anti-forgery token is checked by `guard` for every non-GET request.

## 6. Changes must go through one pipeline

If the module changes anything in an external system, copy the shape of `AdChangeService`: permission, Action Policy validation, a fresh
re-read, allowlists and protected objects, a **dry run**, the change, an audit row with a correlation id, and a result object. Never put
passwords or tokens in results, logs or audit rows (the log filter redacts common patterns, but do not rely on it).

## 7. Tests

* A provider test with the Fake provider (state changes, dry run changes nothing, failure simulations).
* API tests for permissions (including a user with no permissions), the pipeline, and audit rows.
* `tests/test_security.py` will fail until every new route names a permission or is explicitly whitelisted, which is the point.
