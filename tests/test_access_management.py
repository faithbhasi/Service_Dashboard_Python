import pytest

from app import csv_writer, permissions as P
from app.db import AuditResult, GroupMapping
from tests.conftest import ALL_PERMISSIONS


def user_with_role(app, role_name: str, *permissions: str):
    """Gives dev.user a custom role and returns a signed-in client for them."""
    admin = app.client().sign_in("dev.admin")
    res = admin.post("/api/admin/roles", {"name": role_name, "permissions": list(permissions)})
    assert res.status_code == 200
    role_id = res.json()["id"]
    assert admin.put(f"/api/admin/users/{app.user_id('dev.user')}/roles", {"roleIds": [role_id]}).status_code == 204
    return app.client().sign_in("dev.user")


def test_users_without_admin_permissions_are_rejected(app):
    c = app.client().sign_in("dev.helpdesk")
    for url in ("/api/admin/users", "/api/admin/roles", "/api/admin/permissions", "/api/admin/group-mappings"):
        assert c.get(url).status_code == 403
    assert c.post("/api/admin/roles", {"name": "x", "permissions": []}).status_code == 403


def test_denied_api_calls_are_written_to_the_audit_log(app):
    c = app.client().sign_in("dev.helpdesk")
    c.get("/api/admin/users")
    assert any(a.action == "api.access" and a.result == AuditResult.DENIED and "/api/admin/users" in a.target for a in app.audit())


def test_users_cannot_change_their_own_roles_or_disable_themselves(app):
    admin = app.client().sign_in("dev.admin")
    me = app.user_id("dev.admin")
    assert admin.put(f"/api/admin/users/{me}/roles", {"roleIds": [app.role_id("Users")]}).status_code == 403
    assert admin.put(f"/api/admin/users/{me}/status", {"isEnabled": False}).status_code == 403


def test_users_cannot_grant_permissions_they_do_not_hold(app):
    mgr = user_with_role(app, "Access manager", P.ADMIN_USERS_MANAGE, P.ADMIN_ROLES_MANAGE)

    assert mgr.post("/api/admin/roles", {"name": "Sneaky", "permissions": [P.AD_USERS_RESET_PASSWORD]}).status_code == 403

    # Cannot hand out the Admins role either, nor add permissions to the role they hold themselves.
    assert mgr.put(f"/api/admin/users/{app.user_id('dev.helpdesk')}/roles", {"roleIds": [str(P.ADMINS_ID)]}).status_code == 403
    own = app.role_id("Access manager")
    edit = mgr.put(f"/api/admin/roles/{own}", {"name": "Access manager", "permissions": [P.ADMIN_USERS_MANAGE, P.ADMIN_ROLES_MANAGE, P.SETTINGS_MANAGE]})
    assert edit.status_code == 403

    assert any(a.action == "admin.role.create" and a.result == AuditResult.DENIED for a in app.audit())


def test_the_last_admin_assignment_cannot_be_removed_or_disabled(app):
    # A second person who holds every permission (but not the Admins role itself) tries to remove the only Admins assignment.
    other = user_with_role(app, "Super ops", *ALL_PERMISSIONS)
    target = app.user_id("dev.admin")

    assert other.put(f"/api/admin/users/{target}/roles", {"roleIds": []}).status_code == 409
    assert other.put(f"/api/admin/users/{target}/status", {"isEnabled": False}).status_code == 409

    # Once another Okta group mapping to Admins exists, the direct assignment may go.
    admin = app.client().sign_in("dev.admin")
    assert admin.post("/api/admin/group-mappings", {"oktaGroup": "IT-Admins", "roleId": str(P.ADMINS_ID)}).status_code == 200
    assert other.put(f"/api/admin/users/{target}/roles", {"roleIds": []}).status_code == 204

    # ...and now that mapping is the last one.
    with app.db() as db:
        mapping_id = next(m.id for m in db.query(GroupMapping) if m.okta_group == "IT-Admins")
    assert other.delete(f"/api/admin/group-mappings/{mapping_id}").status_code == 409


def test_default_roles_and_assigned_roles_cannot_be_deleted_and_admins_cannot_be_edited(app):
    admin = app.client().sign_in("dev.admin")
    for name in ("Admins", "Auditors and Security", "Users"):
        assert admin.delete(f"/api/admin/roles/{app.role_id(name)}").status_code == 403

    assert admin.put(f"/api/admin/roles/{P.ADMINS_ID}", {"name": "Admins", "permissions": [P.DASHBOARD_READ]}).status_code == 403

    helpdesk = app.role_id("Helpdesk (sample)")  # assigned to dev.helpdesk
    assert admin.delete(f"/api/admin/roles/{helpdesk}").status_code == 409

    fresh = admin.post("/api/admin/roles", {"name": "Temp", "permissions": [P.DASHBOARD_READ]})
    assert admin.delete(f"/api/admin/roles/{fresh.json()['id']}").status_code == 204


def test_roles_can_be_created_cloned_and_edited_and_every_change_is_audited(app):
    admin = app.client().sign_in("dev.admin")
    created = admin.post("/api/admin/roles", {"name": "Reporting", "description": "d", "permissions": [P.DASHBOARD_READ]}).json()
    role_id = created["id"]

    assert admin.post(f"/api/admin/roles/{role_id}/clone", {"name": "Reporting copy"}).status_code == 200
    assert admin.post(f"/api/admin/roles/{role_id}/clone", {"name": "Reporting copy"}).status_code == 409

    assert admin.put(f"/api/admin/roles/{role_id}", {"name": "Reporting", "permissions": [P.DASHBOARD_READ, P.LOGS_READ]}).status_code == 200
    assert admin.put(f"/api/admin/roles/{role_id}", {"name": "Reporting", "permissions": ["not.a.permission"]}).status_code == 400

    actions = [a.action for a in app.audit()]
    assert "admin.role.create" in actions
    assert "admin.role.clone" in actions
    assert "admin.role.update" in actions


def test_user_export_is_audited_and_returns_csv(app):
    admin = app.client().sign_in("dev.admin")
    res = admin.get("/api/admin/users/export")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "Dev Admin" in res.text
    assert any(a.action == "admin.users.export" for a in app.audit())


@pytest.mark.parametrize("value,expected", [
    ("=SUM(A1)", "'=SUM(A1)"), ("+1", "'+1"), ("-2", "'-2"), ("@cmd", "'@cmd"), ("plain", "plain"),
    ("a,b", '"a,b"'), ('say "hi"', '"say ""hi"""'),
])
def test_csv_cells_are_escaped(value, expected):
    assert csv_writer.cell(value) == expected
