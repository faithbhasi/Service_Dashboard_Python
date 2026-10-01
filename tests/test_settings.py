import base64
import json
from datetime import UTC, datetime

from app import permissions as P
from app.db import AuditLog
from app.modules.ad import fake_data as fd
from app.modules.ad.fake_data import fake_id
from app.routers.settings import active_banner
from app.settings_models import BannerSettings, GeneralSettings

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def general(tweak=None, banner=None) -> dict:
    b = {"enabled": False, "type": "Information", "text": "", "startLocal": None, "endLocal": None}
    if banner:
        banner(b)
    g = {"productName": "Test Product", "environmentLabel": "Test", "timeZone": "UTC", "dateFormat": "yyyy-MM-dd", "supportContact": "help@example.invalid",
         "idleTimeoutMinutes": 30, "absoluteTimeoutMinutes": 480, "banner": b}
    if tweak:
        tweak(g)
    return g


# ---------------------------------------------------------------- permissions

def test_settings_endpoints_need_the_right_permission(app):
    auditor = app.client().sign_in("dev.auditor")  # no settings permissions at all
    for url in ("/api/settings/general", "/api/settings/modules", "/api/settings/action-policies", "/api/settings/personalization", "/api/modules/ad/settings"):
        assert auditor.get(url).status_code == 403, url

    helpdesk = app.client().sign_in("dev.helpdesk")
    assert helpdesk.put("/api/settings/general", general()).status_code == 403
    assert helpdesk.put("/api/settings/modules/ad", {"enabled": False}).status_code == 403
    assert helpdesk.put("/api/settings/action-policies", {}).status_code == 403
    assert helpdesk.put("/api/settings/personalization", {}).status_code == 403
    assert helpdesk.post("/api/settings/personalization/reset-colors").status_code == 403
    assert helpdesk.upload("/api/settings/personalization/logo/light", PNG, "x.png").status_code == 403
    assert helpdesk.delete("/api/settings/personalization/logo/light").status_code == 403
    assert helpdesk.put("/api/modules/ad/settings", {}).status_code == 403
    assert helpdesk.post("/api/modules/ad/settings/test-connection").status_code == 403


def test_managing_settings_and_managing_personalization_are_separate_permissions(app):
    admin = app.client().sign_in("dev.admin")
    role = admin.post("/api/admin/roles", {"name": "Branding only", "permissions": [P.SETTINGS_READ, P.SETTINGS_PERSONALIZATION_MANAGE]}).json()
    admin.put(f"/api/admin/users/{app.user_id('dev.user')}/roles", {"roleIds": [role["id"]]})
    c = app.client().sign_in("dev.user")
    assert c.get("/api/settings/personalization").status_code == 200
    assert c.put("/api/settings/general", general()).status_code == 403
    assert c.post("/api/settings/personalization/reset-colors").status_code == 200


# ---------------------------------------------------------------- general

def test_general_settings_are_validated_saved_and_audited_with_before_and_after(app):
    c = app.client().sign_in("dev.admin")

    def put(**kv):
        return c.put("/api/settings/general", general(lambda g: g.update(kv))).status_code

    assert put(timeZone="Mars/Olympus") == 400
    assert put(dateFormat="dd-mm-yy") == 400
    assert put(productName=" ") == 400
    assert put(idleTimeoutMinutes=120, absoluteTimeoutMinutes=60) == 400
    assert put(idleTimeoutMinutes=1) == 400

    assert put(timeZone="Europe/London", productName="Renamed") == 200
    row = app.audit(action="settings.general.update")[0]
    assert '"timeZone":"UTC"' in row.previous_value
    assert '"timeZone":"Europe/London"' in row.new_value
    assert c.get("/api/settings/shell").json()["productName"] == "Renamed"
    assert c.get("/api/settings/branding").json()["productName"] == "Renamed"


# ---------------------------------------------------------------- banner

def test_banner_is_shown_only_between_its_start_and_end_in_the_configured_time_zone():
    g = GeneralSettings(time_zone="Australia/Sydney", banner=BannerSettings(enabled=True, type="Maintenance", text="Maintenance tonight 10pm-11pm",
                                                                             start_local="2026-03-05T22:00", end_local="2026-03-05T23:00"))
    # 22:30 in Sydney (UTC+11 in March) is 11:30 UTC.
    assert active_banner(g, datetime(2026, 3, 5, 11, 30, tzinfo=UTC)) is not None
    assert active_banner(g, datetime(2026, 3, 5, 10, 30, tzinfo=UTC)) is None  # 21:30 local: before
    assert active_banner(g, datetime(2026, 3, 5, 12, 30, tzinfo=UTC)) is None  # 23:30 local: after, hidden automatically
    g.banner.enabled = False
    assert active_banner(g, datetime(2026, 3, 5, 11, 30, tzinfo=UTC)) is None


def test_banner_rules_information_is_dismissible_others_are_not_plain_text_only_and_changes_are_audited(app):
    c = app.client().sign_in("dev.admin")

    def put(**kv):
        return c.put("/api/settings/general", general(banner=lambda b: b.update(kv)))

    assert put(enabled=True, text="<b>Hi</b>").status_code == 400
    assert put(enabled=True, text="x" * 301).status_code == 400
    assert put(enabled=True, text="").status_code == 400
    assert put(enabled=True, text="x", type="Alarm").status_code == 400
    assert put(enabled=True, text="x", startLocal="2026-03-05T10:00", endLocal="2026-03-05T09:00").status_code == 400

    put(enabled=True, type="Information", text="Welcome back")
    info = c.get("/api/settings/shell").json()["banner"]
    assert info["text"] == "Welcome back"
    assert info["dismissible"] is True

    put(enabled=True, type="Warning", text="Slow logons today")
    assert c.get("/api/settings/shell").json()["banner"]["dismissible"] is False

    put(enabled=False, text="Slow logons today")
    assert c.get("/api/settings/shell").json()["banner"] is None

    actions = [a.action for a in app.audit() if a.action.startswith("settings.banner")]
    assert actions == ["settings.banner.create", "settings.banner.update", "settings.banner.remove"]


# ---------------------------------------------------------------- modules

def test_a_disabled_module_answers_every_route_with_the_same_error_and_disappears_from_search_and_the_dashboard(app):
    c = app.client().sign_in("dev.admin")
    id_ = fake_id("user:alice.smith")

    assert c.put("/api/settings/modules/ad", {"enabled": False}).status_code == 200
    for url in ("/api/modules/ad/users", f"/api/modules/ad/users/{id_}", "/api/modules/ad/computers", "/api/modules/ad/groups", "/api/modules/ad/ous", "/api/modules/ad/settings"):
        res = c.get(url)
        assert res.status_code == 403, url
        body = res.json()
        assert body["code"] == "module_disabled"
        assert body["correlationId"]
    assert c.post(f"/api/modules/ad/users/{id_}/unlock", {"justification": "long enough justification"}).status_code == 403

    assert len(c.get("/api/search?q=alice").json()["modules"]) == 0
    cards = [x["key"] for x in c.get("/api/dashboard").json()["cards"]]
    assert "lockedUsers" not in cards
    assert next(m for m in c.get("/api/settings/modules").json() if m["id"] == "ad")["status"] == "Disabled"

    c.put("/api/settings/modules/ad", {"enabled": True})
    assert c.get("/api/modules/ad/users").status_code == 200
    assert len(app.audit(action="settings.modules.update")) == 2


def test_coming_soon_modules_cannot_be_enabled(app):
    c = app.client().sign_in("dev.admin")
    for id_ in ("okta", "m365", "mimecast", "citrix"):
        assert c.put(f"/api/settings/modules/{id_}", {"enabled": True}).status_code == 400
    for m in c.get("/api/settings/modules").json():
        if m["id"] != "ad":
            assert m["status"] == "Coming Soon"


# ---------------------------------------------------------------- action policies

def test_action_policies_are_validated_and_take_effect_immediately(app):
    c = app.client().sign_in("dev.admin")
    policies = c.get("/api/settings/action-policies").json()

    def build(tweak=None, length=16):
        actions = json.loads(json.dumps(policies["actions"]))
        if tweak:
            tweak(actions)
        return {"actions": actions, "mustChangePasswordDefault": True, "generatedPasswordLength": length}

    def bad_pattern(a): a["unlock"]["ticketPattern"] = "([unclosed"
    def zero_min(a): a["unlock"].update(justificationRequired=True, justificationMinLength=0)
    def require_ticket(a): a["unlock"].update(ticketRequired=True, ticketPattern=r"^INC-\d+$")

    assert c.put("/api/settings/action-policies", build(bad_pattern)).status_code == 400
    assert c.put("/api/settings/action-policies", build(length=4)).status_code == 400
    assert c.put("/api/settings/action-policies", build(zero_min)).status_code == 400

    assert c.put("/api/settings/action-policies", build(require_ticket, length=20)).status_code == 200
    assert c.get("/api/settings/shell").json()["actionPolicies"]["generatedPasswordLength"] == 20

    dave = fake_id("user:dave.locked")
    assert c.post(f"/api/modules/ad/users/{dave}/unlock", {"justification": "long enough justification"}).status_code == 400
    assert c.post(f"/api/modules/ad/users/{dave}/unlock", {"justification": "long enough justification", "ticketNumber": "INC-9"}).status_code == 200
    assert any(a.action == "settings.actionPolicies.update" and '"ticketRequired":false' in a.previous_value for a in app.audit())


# ---------------------------------------------------------------- AD integration settings

def test_ad_settings_show_the_connection_read_only_validate_dns_and_are_audited(app):
    c = app.client().sign_in("dev.admin")
    body = c.get("/api/modules/ad/settings").json()
    assert body["connection"]["provider"] == "Fake"
    settings = dict(body["settings"])

    settings["manageableUserOus"] = ["not a dn"]
    assert c.put("/api/modules/ad/settings", settings).status_code == 400
    settings["manageableUserOus"] = ["OU=Elsewhere,DC=other,DC=domain"]
    assert c.put("/api/modules/ad/settings", settings).status_code == 400
    settings["manageableUserOus"] = [fd.CONTRACTORS]
    settings["employeeIdAttribute"] = "employeeID=*)(x"
    assert c.put("/api/modules/ad/settings", settings).status_code == 400
    settings["employeeIdAttribute"] = "employeeNumber"
    settings["searchResultLimit"] = 10
    assert c.put("/api/modules/ad/settings", settings).status_code == 400
    settings["searchResultLimit"] = 500
    assert c.put("/api/modules/ad/settings", settings).status_code == 200

    # The allowlist really changed: Staff is no longer manageable, so the change is denied.
    alice = fake_id("user:alice.smith")
    res = c.post(f"/api/modules/ad/users/{alice}/unlock", {"justification": "long enough justification"})
    assert res.status_code == 403
    assert any(a.action == "settings.ad.update" and "employeeNumber" in a.new_value for a in app.audit())

    test = c.post("/api/modules/ad/settings/test-connection").json()
    assert test["success"] is True
    assert len(test["steps"]) == 4


# ---------------------------------------------------------------- personalization

def colors(primary: str) -> dict:
    return {"primary": primary, "topBarBackground": "#ffffff", "navBackground": "#101820", "navText": "#ffffff", "navSelected": "#203040",
            "pageBackground": "#f0f0f0", "cardBackground": "#ffffff", "sectionHeader": "#101820", "success": "#106020", "warning": "#805000", "error": "#a02020"}


def test_colours_are_validated_saved_audited_and_can_be_reset(app):
    c = app.client().sign_in("dev.admin")
    for bad in ("red", "#12345", "url(x)"):  # no CSS injection
        assert c.put("/api/settings/personalization", {"productName": "P", "light": colors(bad), "dark": colors("#000000")}).status_code == 400

    assert c.put("/api/settings/personalization", {"productName": "Brand", "light": colors("#aa0000"), "dark": colors("#00aa00")}).status_code == 200
    branding = c.get("/api/settings/branding").json()
    assert branding["light"]["primary"] == "#aa0000"
    assert branding["productName"] == "Brand"
    assert any(a.action == "settings.personalization.update" and "#aa0000" in a.new_value and "#1f5fbf" in a.previous_value for a in app.audit())

    c.post("/api/settings/personalization/reset-colors")
    assert c.get("/api/settings/branding").json()["light"]["primary"] == "#1f5fbf"


def test_logos_accept_png_jpeg_webp_by_content_and_refuse_svg_and_oversized_files(make_app):
    app = make_app(extra={"App": {"LogoMaxBytes": 2048}})
    c = app.client().sign_in("dev.admin")
    url = "/api/settings/personalization/logo/light"

    svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"
    assert c.upload(url, svg, "logo.svg", "image/svg+xml").status_code == 400
    assert c.upload(url, svg, "logo.png", "image/png").status_code == 400  # disguised as a PNG
    assert c.upload(url, PNG + bytes(5000), "big.png").status_code == 400
    assert c.upload("/api/settings/personalization/logo/..%2F..%2Fevil", PNG, "x.png").status_code == 404

    assert c.upload(url, PNG, "../../weird name.png").status_code == 200
    logos = app.state.paths.logo_directory
    assert [p.name for p in logos.iterdir()] == ["logoLight.png"]  # the upload name never reaches disk

    anon = app.client()
    served = anon.get(url)
    assert served.status_code == 200
    assert served.headers["content-type"].split(";")[0] == "image/png"
    assert served.content == PNG
    branding = anon.get("/api/settings/branding").json()
    assert branding["hasLogoLight"] is True
    assert branding["hasLogoDark"] is False

    assert c.delete(url).status_code == 204
    assert anon.get(url).status_code == 404
    assert list(logos.iterdir()) == []
    assert len(app.audit(action="settings.personalization.logo")) == 2


def test_the_environment_label_colour_is_validated_saved_and_shown_in_the_shell(app):
    c = app.client().sign_in("dev.admin")
    for bad in ("red", "#12345", "#gggggg", "#1234567", "rgb(1,2,3)", "url(x)"):
        assert c.put("/api/settings/general", general(lambda g, bad=bad: g.update(environmentLabelColor=bad))).status_code == 400
    assert c.get("/api/settings/shell").json()["environmentLabelColor"] == ""  # automatic by default

    assert c.put("/api/settings/general", general(lambda g: g.update(environmentLabelColor="#AA3355"))).status_code == 200
    assert c.get("/api/settings/shell").json()["environmentLabelColor"] == "#aa3355"
    assert c.get("/api/settings/general").json()["environmentLabelColor"] == "#aa3355"

    assert c.put("/api/settings/general", general(lambda g: g.update(environmentLabelColor=""))).status_code == 200  # back to automatic
    assert c.get("/api/settings/shell").json()["environmentLabelColor"] == ""
    assert any(a.action == "settings.general.update" and "aa3355" in a.new_value for a in app.audit())


def test_a_client_that_leaves_the_environment_colour_out_does_not_reset_it(app):
    c = app.client().sign_in("dev.admin")
    assert c.put("/api/settings/general", general(lambda g: g.update(environmentLabelColor="#aa3355"))).status_code == 200
    assert c.put("/api/settings/general", general(lambda g: g.pop("environmentLabelColor", None))).status_code == 200  # an older client
    assert c.get("/api/settings/shell").json()["environmentLabelColor"] == "#aa3355"


__all__ = ["AuditLog"]
