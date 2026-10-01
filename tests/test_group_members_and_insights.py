import uuid
from datetime import UTC, datetime

from app.modules.ad import ldap_text as lt
from app.modules.ad.fake_data import fake_id
from app.modules.ad.provider import ComputerFilter, UserFilter

WHY = "Ticket approved by the line manager"


def user_guid(sam): return fake_id("user:" + sam)
def group_guid(name): return fake_id("group:" + name)
def members(group): return f"/api/modules/ad/groups/{group}/members"


def body(users, typed=None, validate_only=False):
    return {"userIds": [str(u) for u in users], "justification": WHY, "ticketNumber": "INC-1234", "typedConfirmation": typed, "validateOnly": validate_only}


# ---------------------------------------------------------------- filters

def test_department_title_and_os_filters_are_escaped_and_added_to_the_ldap_filter():
    u = lt.users_filter(None, UserFilter.All, "employeeID", datetime.now(UTC), "Sales)(objectClass=*", "Dir*ector")
    assert "(department=*Sales\\29\\28objectClass=\\2a*)" in u
    assert "(title=*Dir\\2aector*)" in u
    c = lt.computers_filter(None, ComputerFilter.All, "windows11")
    assert "(operatingSystem=*Windows 11*)" in c
    assert "operatingSystem" not in lt.computers_filter(None, ComputerFilter.All, "not-a-real-key")


def test_users_can_be_filtered_by_department_and_title_and_computers_by_os(app):
    c = app.client().sign_in("dev.admin")

    sales = c.get("/api/modules/ad/users?department=Sales&pageSize=200").json()
    assert sales["items"]
    assert all(u["department"] == "Sales" for u in sales["items"])

    directors = c.get("/api/modules/ad/users?title=Director&pageSize=200").json()
    assert any(u["samAccountName"] == "carol.white" for u in directors["items"])

    both = c.get("/api/modules/ad/users?department=Engineering&title=Director").json()
    assert [u["samAccountName"] for u in both["items"]] == ["carol.white"]

    servers = c.get("/api/modules/ad/computers?os=windowsserver&pageSize=200").json()
    assert servers["items"]
    assert all("Windows Server" in x["operatingSystem"] for x in servers["items"])

    win11 = c.get("/api/modules/ad/computers?os=windows11&pageSize=200").json()
    assert any(x["name"] == "WS-NOPERM" for x in win11["items"])

    # An unknown OS key is ignored rather than breaking the search.
    assert c.get("/api/modules/ad/computers?os=%29%28objectClass%3D%2A").status_code == 200


# ---------------------------------------------------------------- group members

def test_users_can_be_added_to_and_removed_from_a_group_with_a_result_per_user(app):
    c = app.client().sign_in("dev.admin")
    group = group_guid("GG-Helpdesk")
    alice, bob = user_guid("alice.smith"), user_guid("bob.jones")

    preview = c.post(f"{members(group)}/add", body([alice, bob], validate_only=True)).json()
    assert all(r["status"] == "Validated" for r in preview["results"])

    add = c.post(f"{members(group)}/add", body([alice, bob])).json()
    assert len(add["results"]) == 2
    assert all(r["status"] == "Success" for r in add["results"])

    sams = [m["samAccountName"] for m in c.get(f"{members(group)}?pageSize=100").json()["items"]]
    assert "alice.smith" in sams and "bob.jones" in sams

    again = c.post(f"{members(group)}/add", body([alice])).json()
    assert again["results"][0]["status"] == "Failed"  # same outcome as from the user's own Groups tab
    assert "Already a member" in again["results"][0]["message"]

    remove = c.post(f"{members(group)}/remove", body([alice])).json()
    assert remove["results"][0]["status"] == "Success"
    after = c.get(f"{members(group)}?pageSize=100").json()
    assert not any(m["samAccountName"] == "alice.smith" for m in after["items"])

    # Audited per user, with the group named, so it also shows in the user's own activity.
    assert any("alice.smith" in a.target and "GG-Helpdesk" in a.target for a in app.audit(action="ad.user.groups.add"))


def test_group_member_changes_respect_permissions_protection_and_limits(app):
    help_ = app.client().sign_in("dev.helpdesk")  # can add, cannot remove
    g = group_guid("GG-Helpdesk")
    assert help_.post(f"{members(g)}/remove", body([user_guid("alice.smith")])).status_code == 403
    assert help_.post(f"{members(g)}/add", body([user_guid("alice.smith")])).status_code == 200

    none = app.client().sign_in("dev.noaccess")
    assert none.post(f"{members(g)}/add", body([user_guid("alice.smith")])).status_code == 403
    assert none.get(f"/api/modules/ad/groups/{g}/addable-users?q=al").status_code == 403

    admin = app.client().sign_in("dev.admin")
    protected = admin.post(f"{members(group_guid('Custom-Protected-Admins'))}/add", body([user_guid("alice.smith")])).json()
    assert protected["results"][0]["status"] == "Denied"
    assert admin.post(f"{members(g)}/add", body([])).status_code == 400
    assert admin.post(f"{members(g)}/add", body([uuid.uuid4() for _ in range(51)])).status_code == 400


def test_addable_users_are_found_by_search_and_flagged_when_already_members(app):
    c = app.client().sign_in("dev.admin")
    g = group_guid("GG-Sales")
    assert c.get(f"/api/modules/ad/groups/{g}/addable-users?q=a").json() == []  # too short to search
    found = c.get(f"/api/modules/ad/groups/{g}/addable-users?q=alice").json()
    assert any(u["samAccountName"] == "alice.smith" for u in found)


# ---------------------------------------------------------------- hourly chart

def test_hourly_activity_counts_resets_unlocks_and_lockouts_in_the_right_hours(app):
    c = app.client().sign_in("dev.admin")
    dave = user_guid("dave.locked")

    before = c.get("/api/modules/ad/activity/hourly?hours=24").json()
    assert len(before["points"]) == 24
    assert before["totalLockouts"] >= 1  # the seeded locked accounts
    assert before["totalPasswordResets"] == 0

    assert c.post(f"/api/modules/ad/users/{dave}/reset-password", {
        "newPassword": "Zq7!Vault-Unique-Secret-9", "mustChangeAtNextSignIn": False, "unlockAccount": False, "justification": WHY,
        "ticketNumber": "INC-1", "typedConfirmation": "dave.locked"}).status_code == 200
    assert c.post(f"/api/modules/ad/users/{dave}/unlock", {"justification": WHY, "ticketNumber": "INC-1"}).status_code == 200

    after = c.get("/api/modules/ad/activity/hourly?hours=24").json()
    assert after["totalPasswordResets"] == 1
    assert after["totalUnlocks"] == 1
    assert after["totalLockouts"] == before["totalLockouts"] - 1  # the unlock cleared one
    last = after["points"][-1]  # the current hour is the last bar
    assert last["passwordResets"] == 1
    assert last["unlocks"] == 1

    assert len(c.get("/api/modules/ad/activity/hourly?hours=1").json()["points"]) == 6  # clamped
    none = app.client().sign_in("dev.noaccess")
    assert none.get("/api/modules/ad/activity/hourly").status_code == 403
