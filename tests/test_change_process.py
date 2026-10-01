import uuid

from app import permissions as P
from app.db import AuditResult
from app.modules.ad import fake_data as fd
from app.modules.ad.fake_data import fake_id
from app.settings_models import ActionKeys, ActionPoliciesSettings
from app.settings_service import SettingsService

WHY = "Ticket approved by the line manager"


def body(extra: dict | None = None, typed: str | None = None, validate_only: bool = False) -> dict:
    extra = extra or {}
    return {
        "justification": WHY, "ticketNumber": "INC-1234", "typedConfirmation": typed, "validateOnly": validate_only,
        "targetOu": extra.get("targetOu"), "groupIds": extra.get("groupIds"), "newPassword": extra.get("newPassword"),
        "mustChangeAtNextSignIn": extra.get("mustChangeAtNextSignIn", False), "unlockAccount": extra.get("unlockAccount", False),
    }


def user_guid(sam): return fake_id("user:" + sam)
def group_guid(name): return fake_id("group:" + name)
def computer_guid(name): return fake_id("computer:" + name)
def url(id_, action): return f"/api/modules/ad/users/{id_}/{action}"
def user_of(c, sam): return c.get(f"/api/modules/ad/users/{user_guid(sam)}").json()["user"]


# ---------------------------------------------------------------- permissions

def test_every_change_endpoint_rejects_users_without_its_permission(app):
    helpdesk = app.client().sign_in("dev.helpdesk")  # read, unlock, reset password, add groups only
    id_ = user_guid("alice.smith")
    for action in ("enable", "disable", "move", "groups/remove"):
        assert helpdesk.post(url(id_, action), body()).status_code == 403
    for action in ("enable", "disable", "move"):
        assert helpdesk.post(f"/api/modules/ad/computers/{computer_guid('WS-001')}/{action}", body()).status_code == 403

    none = app.client().sign_in("dev.noaccess")
    for action in ("reset-password", "unlock", "enable", "disable", "move", "groups/add", "groups/remove"):
        assert none.post(url(id_, action), body()).status_code == 403
    assert none.get(f"/api/modules/ad/users/{id_}/addable-groups").status_code == 403

    auditor = app.client().sign_in("dev.auditor")  # read-only
    assert auditor.post(url(id_, "unlock"), body()).status_code == 403


# ---------------------------------------------------------------- the pipeline

def test_unlock_runs_the_full_pipeline_and_is_audited_with_justification_and_ticket(app):
    c = app.client().sign_in("dev.helpdesk")
    dave = user_guid("dave.locked")
    assert user_of(c, "dave.locked")["lockedOut"] is True

    res = c.post(url(dave, "unlock"), body())
    assert res.status_code == 200
    out = res.json()
    assert out["status"] == "Success"
    assert out["correlationId"]
    assert user_of(c, "dave.locked")["lockedOut"] is False

    rows = [a for a in app.audit() if a.action == "ad.user.unlock"]
    assert [r.result for r in rows] == [AuditResult.SUCCESS]  # one row for the change: no extra automatic "Validated" row
    done = rows[0]
    assert done.justification == WHY
    assert done.ticket_number == "INC-1234"
    assert done.target_id == str(dave)
    assert "Locked out: Yes" in done.previous_value
    assert "Locked out: No" in done.new_value
    assert done.correlation_id == out["correlationId"]


def test_unlocking_an_account_that_is_no_longer_locked_makes_no_change_and_says_so(app):
    c = app.client().sign_in("dev.helpdesk")
    out = c.post(url(user_guid("alice.smith"), "unlock"), body()).json()
    assert out["status"] == "NoChange"
    assert "no longer locked" in out["message"]


def test_justification_and_typed_confirmation_are_enforced_from_the_action_policies(app):
    c = app.client().sign_in("dev.admin")
    id_ = user_guid("alice.smith")

    none = c.post(url(id_, "disable"), {"justification": "", "ticketNumber": ""})
    assert none.status_code == 400
    assert "justification" in none.text.lower()
    assert c.post(url(id_, "disable"), {"justification": "short"}).status_code == 400

    # Disabling asks for the typed account name by default.
    assert c.post(url(id_, "disable"), body(typed="nope")).status_code == 400
    assert user_of(c, "alice.smith")["enabled"] is True

    ok = c.post(url(id_, "disable"), body(typed="alice.smith"))
    assert ok.json()["status"] == "Success"
    assert user_of(c, "alice.smith")["enabled"] is False


def test_ticket_number_format_from_the_action_policy_is_enforced(app):
    with app.db() as db:
        policies = ActionPoliciesSettings()
        policies.actions[ActionKeys.UNLOCK].ticket_required = True
        policies.actions[ActionKeys.UNLOCK].ticket_pattern = r"^INC-\d{4}$"
        SettingsService(db, app.state.cache, app.settings.app).save_action_policies(policies, "test")
    c = app.client().sign_in("dev.helpdesk")
    dave = user_guid("dave.locked")
    assert c.post(url(dave, "unlock"), {"justification": WHY}).status_code == 400
    assert c.post(url(dave, "unlock"), {"justification": WHY, "ticketNumber": "bad"}).status_code == 400
    assert c.post(url(dave, "unlock"), {"justification": WHY, "ticketNumber": "INC-1234"}).status_code == 200


# ---------------------------------------------------------------- dry run

def test_validate_only_never_changes_the_directory_and_is_audited_as_validated(app):
    c = app.client().sign_in("dev.helpdesk")
    dave = user_guid("dave.locked")
    res = c.post(url(dave, "unlock"), body(validate_only=True)).json()
    assert res["status"] == "Validated"
    assert res["dryRun"] is True
    assert res["changes"][0]["field"] == "Locked out"
    assert len(res["checks"]) >= 2
    assert user_of(c, "dave.locked")["lockedOut"] is True  # still locked

    rows = [a for a in app.audit() if a.action == "ad.user.unlock"]
    assert len(rows) == 1
    assert rows[0].result == AuditResult.VALIDATED
    assert rows[0].result == "Validated (no change made)"


def test_a_failed_dry_run_blocks_the_real_change(app):
    c = app.client().sign_in("dev.admin")
    no_perm = user_guid("svc.noperm")  # the simulated service account has no rights on this one
    res = c.post(url(no_perm, "disable"), body(typed="svc.noperm"))
    assert res.status_code == 422
    out = res.json()
    assert out["status"] == "Failed"
    assert out["message"].startswith("Validation failed")
    assert any(not ch["passed"] for ch in out["checks"])
    assert user_of(c, "svc.noperm")["enabled"] is True  # nothing was written

    rows = [a for a in app.audit() if a.action == "ad.user.disable"]
    assert not any(r.result == AuditResult.SUCCESS for r in rows)
    assert any(r.result == AuditResult.FAILURE for r in rows)


# ---------------------------------------------------------------- protected groups and OUs, through the API directly

def test_protected_and_non_allowlisted_groups_cannot_be_changed_even_when_sent_directly_to_the_api(app):
    c = app.client().sign_in("dev.admin")
    alice = user_guid("alice.smith")

    for g in ("Domain Admins", "Enterprise Admins", "Administrators", "Backup Operators", "Custom-Protected-Admins", "Domain Users"):
        res = c.post(url(alice, "groups/add"), body({"groupIds": [str(group_guid(g))]})).json()
        assert res["results"][0]["status"] == "Denied"
    m = c.get(f"/api/modules/ad/users/{alice}/groups").json()
    assert not any(g["name"] == "Domain Admins" for g in m["direct"])

    # Removing from a protected group is blocked too (jack.pso is in Custom-Protected-Admins).
    rem = c.post(url(user_guid("jack.pso"), "groups/remove"), body({"groupIds": [str(group_guid("Custom-Protected-Admins"))]})).json()
    assert rem["results"][0]["status"] == "Denied"
    assert any(a.result == AuditResult.DENIED and a.action == "ad.user.groups.add" for a in app.audit())


def test_users_in_protected_or_admin_ous_and_moves_into_them_are_blocked(app):
    c = app.client().sign_in("dev.admin")
    alice = user_guid("alice.smith")

    for ou in (fd.TIER0, fd.DOMAIN_CONTROLLERS, fd.SERVICE_ACCOUNTS, fd.SERVERS):
        res = c.post(url(alice, "move"), body({"targetOu": ou}))
        assert res.status_code == 403
        assert res.json()["status"] == "Denied"
    assert "Engineering" in user_of(c, "alice.smith")["ou"]

    # Objects already sitting in a blocked OU cannot be changed at all.
    tier0_user = user_guid("adm.tier0")
    assert c.post(url(tier0_user, "unlock"), body()).status_code == 403
    assert c.post(url(tier0_user, "move"), body({"targetOu": fd.CONTRACTORS})).status_code == 403
    assert c.post(url(user_guid("svc.backup"), "disable"), body(typed="svc.backup")).status_code == 403

    # A valid move to an allowed OU works.
    ok = c.post(url(alice, "move"), body({"targetOu": fd.CONTRACTORS}))
    assert ok.json()["status"] == "Success"
    assert user_of(c, "alice.smith")["ou"].startswith("OU=Contractors")


def test_malformed_or_outside_domain_ous_are_rejected(app):
    c = app.client().sign_in("dev.admin")
    for bad in ("not a dn", "OU=X,DC=other,DC=domain", ""):
        assert c.post(url(user_guid("alice.smith"), "move"), body({"targetOu": bad})).status_code == 400


def test_computers_can_be_disabled_and_moved_within_allowed_ous_only(app):
    c = app.client().sign_in("dev.admin")
    ws = computer_guid("WS-001")

    def u(a): return f"/api/modules/ad/computers/{ws}/{a}"

    assert c.post(u("disable"), body(typed="WS-001")).json()["status"] == "Success"
    assert c.get(f"/api/modules/ad/computers/{ws}").json()["computer"]["enabled"] is False
    assert c.post(u("enable"), body()).json()["status"] == "Success"

    assert c.post(u("move"), body({"targetOu": fd.SERVERS})).status_code == 403
    assert c.post(u("move"), body({"targetOu": fd.LAPTOPS})).json()["status"] == "Success"

    # Domain controllers are always blocked.
    assert c.post(f"/api/modules/ad/computers/{computer_guid('DC01')}/disable", body(typed="DC01")).status_code == 403


# ---------------------------------------------------------------- group membership

def test_adding_to_several_groups_reports_each_one_and_the_primary_group_cannot_be_removed(app):
    c = app.client().sign_in("dev.admin")
    alice = user_guid("alice.smith")  # already in GG-VPN-Users, not in GG-Helpdesk

    addable = c.get(f"/api/modules/ad/users/{alice}/addable-groups").json()
    names = [g["name"] for g in addable]
    assert "GG-Helpdesk" in names
    assert "Domain Admins" not in names
    assert "Domain Users" not in names
    assert next(g for g in addable if g["name"] == "GG-VPN-Users")["alreadyMember"] is True

    res = c.post(url(alice, "groups/add"), body({"groupIds": [str(group_guid(n)) for n in ("GG-Helpdesk", "GG-VPN-Users", "APP-CRM-Users")]})).json()
    by_group = {r["groupName"]: r for r in res["results"]}
    assert by_group["GG-Helpdesk"]["status"] == "Success"
    assert by_group["GG-VPN-Users"]["status"] == "Failed"
    assert "Already a member" in by_group["GG-VPN-Users"]["message"]
    assert by_group["APP-CRM-Users"]["status"] == "Success"

    rem = c.post(url(alice, "groups/remove"), body({"groupIds": [str(group_guid("GG-Helpdesk"))]})).json()
    assert rem["results"][0]["status"] == "Success"
    primary = c.post(url(alice, "groups/remove"), body({"groupIds": [str(group_guid("Domain Users"))]})).json()
    assert primary["results"][0]["status"] == "Denied"


def test_a_change_made_after_a_review_leaves_one_validation_row_and_one_result_row(app):
    c = app.client().sign_in("dev.helpdesk")
    dave = user_guid("dave.locked")
    # What the confirmation screen does: a dry run for the review step, then the real change.
    assert c.post(url(dave, "unlock"), body(validate_only=True)).status_code == 200
    assert c.post(url(dave, "unlock"), body()).status_code == 200
    rows = [a for a in app.audit() if a.action == "ad.user.unlock"]
    assert [r.result for r in rows] == [AuditResult.VALIDATED, AuditResult.SUCCESS]  # not two validations before the change


# ---------------------------------------------------------------- password reset

def test_resetting_a_password_cannot_be_used_to_unlock_without_the_unlock_permission(app):
    admin = app.client().sign_in("dev.admin")
    created = admin.post("/api/admin/roles", {"name": "Reset only", "permissions": [P.AD_USERS_READ, P.AD_USERS_RESET_PASSWORD]})
    admin.put(f"/api/admin/users/{app.user_id('dev.user')}/roles", {"roleIds": [created.json()["id"]]})
    c = app.client().sign_in("dev.user")
    dave = user_guid("dave.locked")

    unlock_too = c.post(url(dave, "reset-password"), body({"newPassword": "Zq7!Vault-Unique-Secret-9", "unlockAccount": True}, typed="dave.locked"))
    assert unlock_too.status_code == 403
    assert "unlock permission" in unlock_too.text
    assert user_of(c, "dave.locked")["lockedOut"] is True  # nothing changed

    # The same person can still reset the password on its own.
    reset_only = c.post(url(dave, "reset-password"), body({"newPassword": "Zq7!Vault-Unique-Secret-9", "unlockAccount": False}, typed="dave.locked"))
    assert reset_only.status_code == 200
    assert user_of(c, "dave.locked")["lockedOut"] is True


def test_password_reset_works_and_the_password_never_appears_in_logs_audit_or_responses(app):
    c = app.client().sign_in("dev.helpdesk")
    dave = user_guid("dave.locked")
    secret = "Zq7!Vault-Unique-Secret-9"

    preview = c.post(url(dave, "reset-password"), body(validate_only=True))
    assert preview.status_code == 200

    res = c.post(url(dave, "reset-password"), body({"newPassword": secret, "mustChangeAtNextSignIn": True, "unlockAccount": True}, typed="dave.locked"))
    assert res.status_code == 200
    assert "Success" in res.text

    user = user_of(c, "dave.locked")
    assert user["passwordStatus"] == "MustChange"
    assert user["lockedOut"] is False

    # A rejected password (policy) must not be echoed either.
    rejected = c.post(url(user_guid("kim.sparse"), "reset-password"), body({"newPassword": "aB1"}, typed="kim.sparse"))
    assert rejected.status_code == 422
    assert "password policy" in rejected.text
    assert 'aB1"' not in rejected.text

    # A bad request shape must not echo it.
    bad = c.post(url(dave, "reset-password"), {"newPassword": secret, "justification": "x"})

    import json

    audit = json.dumps([{k: v for k, v in a.__dict__.items() if not k.startswith("_")} for a in app.audit()], default=str)
    logs = app.logs.all_text()
    assert "reset-password" in logs  # the capture works, so the absence below means something
    for name, text in (("preview", preview.text), ("response", res.text), ("rejected", rejected.text), ("bad request", bad.text), ("audit", audit), ("logs", logs)):
        assert secret not in text, f"the password leaked into the {name}"
        assert "weakpw-Echo-Check" not in text
    assert any(a.action == "ad.user.resetPassword" and a.result == AuditResult.SUCCESS and "not shown" in a.new_value for a in app.audit())


def test_password_reset_requires_a_password_unless_only_validating(app):
    c = app.client().sign_in("dev.helpdesk")
    assert c.post(url(user_guid("dave.locked"), "reset-password"), body(typed="dave.locked")).status_code == 400


# ---------------------------------------------------------------- failures

def test_a_directory_outage_is_audited_as_a_failure_and_returns_503(app):
    c = app.client().sign_in("dev.helpdesk")
    app.state.provider.simulation.server_unavailable = True
    res = c.post(url(user_guid("dave.locked"), "unlock"), body())
    assert res.status_code == 503
    assert any(a.action == "ad.user.unlock" and a.result == AuditResult.FAILURE for a in app.audit())


def test_an_unknown_object_is_reported_and_audited(app):
    c = app.client().sign_in("dev.helpdesk")
    res = c.post(url(uuid.uuid4(), "unlock"), body())
    assert res.status_code == 422
    assert res.json()["errorCode"] == "NotFound"
    assert any(a.action == "ad.user.unlock" and a.result == AuditResult.FAILURE for a in app.audit())
