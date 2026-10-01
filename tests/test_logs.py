import sqlite3
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from app.db import AuditCategory, AuditLog, AuditResult
from app.modules.ad.fake_data import fake_id


def add_rows(app, *rows: AuditLog) -> None:
    with app.db() as db:
        db.add_all(rows)
        db.commit()


def row(action, user, user_name, result=AuditResult.SUCCESS, cat=AuditCategory.Admin, target=None, ticket=None, at=None) -> AuditLog:
    return AuditLog(action=action, user_id=user, user_name=user_name, result=result, category=cat, target=target, ticket_number=ticket,
                    time_utc=at or datetime.now(UTC))


def total(c, url) -> int:
    return c.get(url).json()["total"]


# ---------------------------------------------------------------- permissions and scope

def test_log_endpoints_reject_users_without_a_logs_permission(app):
    none = app.client().sign_in("dev.noaccess")
    for url in ("/api/logs/logons", "/api/logs/access", "/api/logs/admin", "/api/logs/user-activity", "/api/logs/entry/1", "/api/logs/users",
                "/api/logs/users-by", "/api/logs/admin/export"):
        assert none.get(url).status_code == 403, url


def test_people_with_only_logs_read_own_see_only_their_own_records_whatever_they_ask_for(app):
    admin = app.client().sign_in("dev.admin")
    helpdesk = app.client().sign_in("dev.helpdesk")
    admin_id = app.user_id("dev.admin")
    add_rows(app, row("ad.user.unlock", admin_id, "Dev Admin", target="someone"),
             row("ad.user.unlock", app.user_id("dev.helpdesk"), "Dev Helpdesk", target="mine"))

    mine = helpdesk.get(f"/api/logs/admin?userId={admin_id}").json()  # asking for someone else's records
    assert all(r["userId"] == app.user_id("dev.helpdesk") for r in mine["items"])
    assert total(admin, "/api/logs/admin") > total(helpdesk, "/api/logs/admin")

    # Cannot open another person's entry, pick users, or use the cross-user reports.
    others = next(a.id for a in app.audit() if a.user_id == admin_id)
    assert helpdesk.get(f"/api/logs/entry/{others}").status_code == 404
    assert admin.get(f"/api/logs/entry/{others}").status_code == 200
    assert helpdesk.get("/api/logs/users").status_code == 403
    assert helpdesk.get("/api/logs/users-by").status_code == 403


# ---------------------------------------------------------------- filters and paging

def test_logs_are_split_by_tab_and_filter_by_date_user_action_result_target_and_ticket(app):
    auditor = app.client().sign_in("dev.auditor")
    uid = app.user_id("dev.admin")
    old = datetime.now(UTC) - timedelta(days=10)
    add_rows(
        app,
        row("logon.signin", uid, "Dev Admin", cat=AuditCategory.Logon),
        row("page.view", uid, "Dev Admin", cat=AuditCategory.Access, target="settings"),
        row("ad.user.disable", uid, "Dev Admin", AuditResult.FAILURE, target="alice.smith (Alice Smith)", ticket="INC-777"),
        row("ad.user.enable", uid, "Dev Admin", target="bob.jones", ticket="INC-888"),
        row("ad.user.enable", uid, "Dev Admin", target="old.one", at=old))

    assert total(auditor, "/api/logs/logons") >= 2  # includes the auditor's own sign-in
    assert total(auditor, "/api/logs/access") >= 1
    assert total(auditor, "/api/logs/admin?result=Failure&action=ad.user.disable") == 1
    assert total(auditor, "/api/logs/admin?target=alice") == 1
    assert total(auditor, "/api/logs/admin?ticket=INC-888") == 1
    assert total(auditor, "/api/logs/admin?action=ad.user.enable") == 2
    recent = quote((datetime.now(UTC) - timedelta(days=1)).isoformat())
    assert total(auditor, f"/api/logs/admin?action=ad.user.enable&from={recent}") == 1
    assert total(auditor, "/api/logs/admin?target=100%25") == 0  # LIKE wildcards in user text are escaped
    assert total(auditor, f"/api/logs/user-activity?userId={uid}") >= 5  # every category

    page = auditor.get("/api/logs/admin?pageSize=1&page=2").json()
    assert len(page["items"]) == 1
    assert page["page"] == 2
    assert auditor.get("/api/logs/nonsense").status_code == 404

    by = auditor.get("/api/logs/users-by?action=ad.user.enable").json()
    assert by[0]["count"] == 2


def test_admin_actions_show_before_and_after_values_and_a_detail_record(app):
    admin = app.client().sign_in("dev.admin")
    admin.post(f"/api/modules/ad/users/{fake_id('user:dave.locked')}/unlock", {"justification": "Verified caller identity by phone"})
    listing = admin.get("/api/logs/admin?action=ad.user.unlock&result=Success").json()
    r = listing["items"][0]
    assert "Locked out: Yes" in r["previousValue"]
    detail = admin.get(f"/api/logs/entry/{r['id']}").json()
    assert detail["justification"] == "Verified caller identity by phone"
    assert detail["correlationId"]


# ---------------------------------------------------------------- export

def test_export_needs_logs_export_is_audited_and_neutralises_spreadsheet_formulas(app):
    helpdesk = app.client().sign_in("dev.helpdesk")
    assert helpdesk.get("/api/logs/admin/export").status_code == 403

    uid = app.user_id("dev.admin")
    add_rows(app, row("ad.user.disable", uid, "=cmd|' /C calc'!A1", target="+SUM(1+1)", ticket="@evil"))
    auditor = app.client().sign_in("dev.auditor")
    res = auditor.get("/api/logs/admin/export?action=ad.user.disable")
    assert res.status_code == 200
    assert "attachment" in res.headers["content-disposition"]
    csv = res.text
    assert "'=cmd|" in csv
    assert "'+SUM(1+1)" in csv
    assert "'@evil" in csv
    assert ",=cmd" not in csv
    assert "Time (UTC),Category,User,Action" in csv

    export = app.audit(action="logs.export")[0]
    assert export.result == AuditResult.SUCCESS
    assert "action 'ad.user.disable'" in export.new_value
    assert export.user_id == app.user_id("dev.auditor")


def test_export_over_the_row_limit_asks_the_user_to_narrow_the_filter(make_app):
    app = make_app(extra={"App": {"ExportRowLimit": 3}})
    uid = app.user_id("dev.admin")
    add_rows(app, *[row("ad.user.enable", uid, "Dev Admin", target=f"t{i}") for i in range(5)])
    auditor = app.client().sign_in("dev.auditor")
    res = auditor.get("/api/logs/admin/export")
    assert res.status_code == 400
    assert "Narrow the filter" in res.text
    assert any(a.action == "logs.export" and a.result == AuditResult.FAILURE for a in app.audit())
    assert auditor.get("/api/logs/admin/export?action=ad.user.enable&target=t1").status_code == 200


# ---------------------------------------------------------------- object history

def test_object_activity_history_lists_changes_made_through_the_app(app):
    helpdesk = app.client().sign_in("dev.helpdesk")
    dave = fake_id("user:dave.locked")
    helpdesk.post(f"/api/modules/ad/users/{dave}/unlock", {"justification": "Caller verified by phone"})
    hist = helpdesk.get(f"/api/modules/ad/users/{dave}/activity").json()
    assert any(r["action"] == "ad.user.unlock" for r in hist["items"])

    none = app.client().sign_in("dev.user")  # no ad.users.read
    assert none.get(f"/api/modules/ad/users/{dave}/activity").status_code == 403


# ---------------------------------------------------------------- retention and backup

def test_retention_removes_old_audit_rows_and_logs_that_it_did(make_app):
    app = make_app(extra={"App": {"AuditRetentionDays": 30}})
    uid = app.user_id("dev.admin")
    now = datetime.now(UTC)
    add_rows(app, row("old.action", uid, "x", at=now - timedelta(days=90)), row("old.action", uid, "x", at=now - timedelta(days=31)), row("new.action", uid, "x"))
    removed = app.asgi.state.maintenance.purge_audit()
    assert removed == 2
    rows = app.audit()
    assert not any(a.action == "old.action" for a in rows)
    assert any(a.action == "new.action" for a in rows)
    assert any(a.action == "maintenance.auditRetention" and "Removed 2" in a.new_value for a in rows)


def test_online_backup_writes_a_consistent_copy_with_the_logo_folder_and_keeps_only_the_newest(make_app):
    app = make_app(extra={"App": {"BackupRetentionCount": 2}})
    app.client().sign_in("dev.admin")  # creates data
    paths = app.state.paths
    (paths.logo_directory / "logoLight.png").write_text("fake")
    tasks = app.asgi.state.maintenance
    folders = []
    for _ in range(3):
        folders.append(tasks.backup())
        time.sleep(0.03)
    assert all(folders)
    from pathlib import Path

    assert not Path(folders[0]).exists()  # pruned
    assert Path(folders[1]).exists() and Path(folders[2]).exists()

    copy = Path(folders[2]) / "service-dashboard.db"
    assert (Path(folders[2]) / "assets" / "logos" / "logoLight.png").exists()
    conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'logon.signin'").fetchone()[0] >= 1
    finally:
        conn.close()
    assert any(a.action == "maintenance.backup" for a in app.audit())
