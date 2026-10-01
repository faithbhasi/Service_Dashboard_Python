"""Which OUs and groups each role may manage, inside the global allowlists."""
from urllib.parse import quote

from sqlalchemy import select

from app import permissions as P
from app.db import AuditResult, Role
from app.modules.ad import fake_data as fd
from app.modules.ad.fake_data import fake_id

WHY = "Ticket approved by the line manager"
CONTRACTORS = fd.CONTRACTORS


def user_guid(sam): return fake_id("user:" + sam)
def group_guid(name): return fake_id("group:" + name)
def group_dn(name): return f"CN={name},{fd.GROUPS_OU}"
def body(validate_only=False): return {"justification": WHY, "ticketNumber": "INC-1", "validateOnly": validate_only, "typedConfirmation": None}
def groups_body(group): return {"justification": WHY, "ticketNumber": "INC-1", "groupIds": [str(group)]}


def role_of(admin, name):
    return next(r for r in admin.get("/api/admin/roles").json() if r["name"] == name)


def role_row(app, name):
    with app.db() as db:
        r = db.scalars(select(Role).where(Role.name == name)).one()
        return r.id, r.name, r.description, [p.permission for p in r.permissions]


def set_scope(admin, app, role, scope):
    rid, name, description, perms = role_row(app, role)
    return admin.put(f"/api/admin/roles/{rid}", {"name": name, "description": description, "permissions": perms, "adScope": scope})


def test_the_scope_options_are_the_global_manageable_lists(app):
    admin = app.client().sign_in("dev.admin")
    o = admin.get("/api/admin/roles/ad-scope-options").json()
    assert any(x["dn"] == CONTRACTORS and x["label"] == "Corp / Contractors" for x in o["userOus"])
    assert any(x["dn"] == fd.LAPTOPS for x in o["computerOus"])
    assert any(x["label"] == "GG-Sales" for x in o["groups"])
    help_ = app.client().sign_in("dev.helpdesk")
    assert help_.get("/api/admin/roles/ad-scope-options").status_code == 403


def test_a_role_limited_to_some_ous_and_groups_can_only_change_those(app):
    admin = app.client().sign_in("dev.admin")
    saved = set_scope(admin, app, "Helpdesk (sample)", {"userOus": [CONTRACTORS], "computerOus": None, "groups": [group_dn("GG-Sales")]})
    assert saved.status_code == 200
    assert role_of(admin, "Helpdesk (sample)")["adScope"]["userOus"] == [CONTRACTORS]

    help_ = app.client().sign_in("dev.helpdesk")
    # dave.locked is in Staff: the global list allows it, the role does not.
    denied = help_.post(f"/api/modules/ad/users/{user_guid('dave.locked')}/unlock", body())
    assert denied.status_code == 403
    assert "Your role is not allowed to manage objects in this OU" in denied.text
    dave = help_.get(f"/api/modules/ad/users/{user_guid('dave.locked')}").json()
    assert dave["ouManageable"] is False
    assert "Your role" in dave["ouReason"]
    assert dave["user"]["lockedOut"] is True  # nothing changed

    # kim.sparse is a contractor: allowed. Groups are limited too.
    kim = user_guid("kim.sparse")
    assert help_.get(f"/api/modules/ad/users/{kim}").json()["ouManageable"] is True
    ok = help_.post(f"/api/modules/ad/users/{kim}/groups/add", groups_body(group_guid("GG-Sales"))).json()
    assert ok["results"][0]["status"] == "Success"
    blocked = help_.post(f"/api/modules/ad/users/{kim}/groups/add", groups_body(group_guid("GG-Finance"))).json()
    assert blocked["results"][0]["status"] == "Denied"
    assert "Your role is not allowed to manage this group" in blocked["results"][0]["message"]

    # The groups the role may add to, and what the group list says is manageable, follow the scope.
    addable = help_.get(f"/api/modules/ad/users/{kim}/addable-groups").json()
    assert [g["name"] for g in addable] == ["GG-Sales"]
    assert help_.get(f"/api/modules/ad/groups/{group_guid('GG-Finance')}").json()["isManageable"] is False
    assert help_.get(f"/api/modules/ad/groups/{group_guid('GG-Sales')}").json()["isManageable"] is True

    # Adding members from the group's own page is held to the same scope.
    via_group = help_.post(f"/api/modules/ad/groups/{group_guid('GG-Finance')}/members/add", {"justification": WHY, "ticketNumber": "INC-1", "userIds": [str(kim)]}).json()
    assert via_group["results"][0]["status"] == "Denied"

    # Admins are never limited, and the audit trail shows the denial.
    assert admin.post(f"/api/modules/ad/users/{user_guid('dave.locked')}/unlock", body()).status_code == 200
    assert any(a.action == "ad.user.unlock" and a.result == AuditResult.DENIED and "Your role" in a.error for a in app.audit())


def test_a_role_with_no_scope_keeps_working_as_before_and_an_empty_list_means_nothing(app):
    admin = app.client().sign_in("dev.admin")
    help_ = app.client().sign_in("dev.helpdesk")
    assert help_.post(f"/api/modules/ad/users/{user_guid('dave.locked')}/unlock", body()).status_code == 200

    set_scope(admin, app, "Helpdesk (sample)", {"userOus": []})
    assert help_.post(f"/api/modules/ad/users/{user_guid('kim.sparse')}/unlock", body()).status_code == 403

    # Putting it back to "all allowed" (null) lifts the limit.
    set_scope(admin, app, "Helpdesk (sample)", {"userOus": None})
    assert help_.post(f"/api/modules/ad/users/{user_guid('kim.sparse')}/unlock", body()).status_code == 200


def test_a_second_role_that_can_change_things_widens_the_reach_but_a_read_only_role_does_not(app):
    admin = app.client().sign_in("dev.admin")
    set_scope(admin, app, "Helpdesk (sample)", {"userOus": [CONTRACTORS]})
    help_ = app.user_id("dev.helpdesk")

    # Auditors are read-only: having that role as well must not lift the helpdesk limit.
    assert admin.put(f"/api/admin/users/{help_}/roles", {"roleIds": [app.role_id("Helpdesk (sample)"), app.role_id(P.AUDITORS)]}).status_code == 204
    c = app.client().sign_in("dev.helpdesk")
    assert c.post(f"/api/modules/ad/users/{user_guid('dave.locked')}/unlock", body()).status_code == 403

    # A second helpdesk-style role limited to Staff adds Staff to what this person can manage.
    created = admin.post("/api/admin/roles", {"name": "Staff helpdesk", "permissions": [P.AD_USERS_READ, P.AD_USERS_UNLOCK], "adScope": {"userOus": [fd.STAFF]}})
    assert created.status_code == 200
    admin.put(f"/api/admin/users/{help_}/roles", {"roleIds": [app.role_id("Helpdesk (sample)"), app.role_id("Staff helpdesk")]})
    c2 = app.client().sign_in("dev.helpdesk")
    assert c2.post(f"/api/modules/ad/users/{user_guid('dave.locked')}/unlock", body()).status_code == 200


def test_scope_entries_must_be_on_the_global_list_and_the_change_is_audited(app):
    admin = app.client().sign_in("dev.admin")
    bad = set_scope(admin, app, "Helpdesk (sample)", {"userOus": [fd.SERVERS]})
    assert bad.status_code == 400
    assert "not on the manageable list" in bad.text

    assert set_scope(admin, app, "Helpdesk (sample)", {"userOus": [CONTRACTORS]}).status_code == 200
    row = [a for a in app.audit() if a.action == "admin.role.update"][-1]
    assert "AD scope" in row.new_value
    assert "Corp" in row.new_value
    assert "AD scope" not in (row.previous_value or "")

    # Cloning keeps the scope.
    clone = admin.post(f"/api/admin/roles/{app.role_id('Helpdesk (sample)')}/clone", {"name": "Helpdesk copy"}).json()
    assert clone["adScope"]["userOus"][0] == CONTRACTORS


def test_nobody_can_widen_a_scope_beyond_their_own_reach(app):
    admin = app.client().sign_in("dev.admin")
    # A manager who can change users in Contractors only, and who may edit roles.
    created = admin.post("/api/admin/roles", {
        "name": "Limited manager", "adScope": {"userOus": [CONTRACTORS]},
        "permissions": [P.AD_USERS_READ, P.AD_USERS_UNLOCK, P.ADMIN_USERS_MANAGE, P.ADMIN_ROLES_MANAGE]})
    assert created.status_code == 200
    admin.put(f"/api/admin/users/{app.user_id('dev.user')}/roles", {"roleIds": [app.role_id("Limited manager")]})
    mgr = app.client().sign_in("dev.user")

    # Giving a role the Staff OU (which they cannot manage) is refused; giving one their own OU is fine.
    wide = mgr.post("/api/admin/roles", {"name": "Wide", "permissions": [P.AD_USERS_UNLOCK], "adScope": {"userOus": [fd.STAFF]}})
    assert wide.status_code == 403
    unrestricted = mgr.post("/api/admin/roles", {"name": "Everything", "permissions": [P.AD_USERS_UNLOCK]})
    assert unrestricted.status_code == 403
    fine = mgr.post("/api/admin/roles", {"name": "Narrow", "permissions": [P.AD_USERS_UNLOCK], "adScope": {"userOus": [CONTRACTORS]}})
    assert fine.status_code == 200

    # They cannot hand a broader existing role to someone either.
    set_scope(admin, app, "Helpdesk (sample)", {"userOus": [fd.STAFF]})
    assign = mgr.put(f"/api/admin/users/{app.user_id('dev.noaccess')}/roles", {"roleIds": [app.role_id("Helpdesk (sample)")]})
    assert assign.status_code == 403


def test_someone_who_cannot_change_computers_cannot_widen_what_a_role_may_manage_there(app):
    admin = app.client().sign_in("dev.admin")
    admin.post("/api/admin/roles", {"name": "Laptop team", "adScope": {"computerOus": [fd.LAPTOPS]},
                                    "permissions": [P.AD_COMPUTERS_READ, P.AD_COMPUTERS_ENABLE]})
    # Access managers who hold no computer permission: they may narrow the scope but not widen it.
    admin.post("/api/admin/roles", {"name": "Access only", "permissions": [P.ADMIN_ROLES_MANAGE, P.ADMIN_USERS_MANAGE]})
    admin.put(f"/api/admin/users/{app.user_id('dev.user')}/roles", {"roleIds": [app.role_id("Access only")]})
    mgr = app.client().sign_in("dev.user")
    rid, _, _, perms = role_row(app, "Laptop team")

    def b(scope):
        return {"name": "Laptop team", "permissions": perms, "adScope": scope}

    assert mgr.put(f"/api/admin/roles/{rid}", b({"computerOus": [fd.LAPTOPS, fd.WORKSTATIONS]})).status_code == 403
    assert mgr.put(f"/api/admin/roles/{rid}", b({"computerOus": None})).status_code == 403
    assert mgr.put(f"/api/admin/roles/{rid}", b({"computerOus": []})).status_code == 200  # narrowing is fine


# ---------------------------------------------------------------- the OU tree

def tree(c, kind, parent=None, q=None):
    url = f"/api/admin/roles/ad-ou-tree?kind={kind}" + ("" if parent is None else "&parent=" + quote(parent, safe="")) + ("" if q is None else "&q=" + quote(q, safe=""))
    return c.get(url).json()


def node(nodes, **match):
    return next(n for n in nodes if all(n[k] == v for k, v in match.items()))


def test_the_whole_ou_tree_can_be_browsed_and_only_ous_inside_the_manageable_lists_can_be_chosen(app):
    admin = app.client().sign_in("dev.admin")
    roots = tree(admin, "users")
    corp = node(roots, dn=fd.CORP)
    assert corp["selectable"] is False  # browsable, but not itself on the manageable list
    assert corp["hasChildren"] is True
    assert any(n["dn"] == fd.DOMAIN_CONTROLLERS and not n["selectable"] for n in roots)

    inside = tree(admin, "users", fd.CORP)
    assert node(inside, dn=fd.STAFF)["selectable"] is True
    assert node(inside, dn=fd.SERVERS)["selectable"] is False
    assert node(inside, dn=fd.SERVERS)["reason"]

    # Sub-OUs of a manageable OU can be chosen, and the two kinds use their own lists.
    assert node(tree(admin, "users", fd.STAFF), name="Sales")["selectable"] is True
    assert node(tree(admin, "computers", fd.CORP), dn=fd.LAPTOPS)["selectable"] is True
    assert any(n["dn"] == "OU=Sales," + fd.STAFF for n in tree(admin, "users", q="Sales"))

    assert admin.get("/api/admin/roles/ad-ou-tree?kind=groups").status_code == 400
    assert app.client().sign_in("dev.helpdesk").get("/api/admin/roles/ad-ou-tree?kind=users").status_code == 403


def test_a_role_can_be_limited_to_one_sub_ou_and_covers_what_is_below_it(app):
    admin = app.client().sign_in("dev.admin")
    sales = "OU=Sales," + fd.STAFF
    assert set_scope(admin, app, "Helpdesk (sample)", {"userOus": [sales]}).status_code == 200

    help_ = app.client().sign_in("dev.helpdesk")
    # dave.locked is in Staff/Sales: allowed. alice.smith is in Staff/Engineering: the global list allows it, the role does not.
    assert help_.post(f"/api/modules/ad/users/{user_guid('dave.locked')}/unlock", body()).status_code == 200
    denied = help_.post(f"/api/modules/ad/users/{user_guid('alice.smith')}/unlock", body())
    assert denied.status_code == 403
    assert "Your role" in denied.text

    # A sub-OU of something the global list does not allow cannot be chosen, nor can a made-up one.
    assert set_scope(admin, app, "Helpdesk (sample)", {"userOus": ["OU=Sales," + fd.SERVERS]}).status_code == 400
    assert set_scope(admin, app, "Helpdesk (sample)", {"userOus": ["not a dn"]}).status_code == 400
    # An entry that was already there stays even after a save that does not touch it.
    assert set_scope(admin, app, "Helpdesk (sample)", {"userOus": [sales], "groups": [group_dn("GG-Sales")]}).status_code == 200


def test_a_limited_manager_can_hand_out_a_sub_ou_of_their_own_but_not_a_sibling(app):
    admin = app.client().sign_in("dev.admin")
    admin.post("/api/admin/roles", {"name": "Staff manager", "adScope": {"userOus": [fd.STAFF]},
                                    "permissions": [P.AD_USERS_READ, P.AD_USERS_UNLOCK, P.ADMIN_ROLES_MANAGE, P.ADMIN_USERS_MANAGE]})
    admin.put(f"/api/admin/users/{app.user_id('dev.user')}/roles", {"roleIds": [app.role_id("Staff manager")]})
    mgr = app.client().sign_in("dev.user")
    narrower = mgr.post("/api/admin/roles", {"name": "Sales only", "permissions": [P.AD_USERS_UNLOCK], "adScope": {"userOus": ["OU=Sales," + fd.STAFF]}})
    assert narrower.status_code == 200  # below their own Staff OU: fine
    sibling = mgr.post("/api/admin/roles", {"name": "Contractors only", "permissions": [P.AD_USERS_UNLOCK], "adScope": {"userOus": [CONTRACTORS]}})
    assert sibling.status_code == 403
    # The tree they see marks what is outside their own reach.
    t = tree(mgr, "users", fd.CORP)
    assert node(t, dn=CONTRACTORS)["selectable"] is False
    assert node(t, dn=fd.STAFF)["selectable"] is True


def test_a_made_up_ou_under_an_allowed_ou_cannot_be_chosen_and_the_options_follow_the_managers_reach(app):
    admin = app.client().sign_in("dev.admin")
    assert set_scope(admin, app, "Helpdesk (sample)", {"userOus": ["OU=DoesNotExist," + fd.STAFF]}).status_code == 400
    assert set_scope(admin, app, "Helpdesk (sample)", {"userOus": ["OU=Sales," + fd.STAFF + ",DC=other,DC=domain"]}).status_code == 400

    # A manager limited to Staff is offered only what they could hand out themselves (so "Limit users" does not start with a 403).
    admin.post("/api/admin/roles", {"name": "Staff manager", "adScope": {"userOus": [fd.STAFF]},
                                    "permissions": [P.AD_USERS_READ, P.AD_USERS_UNLOCK, P.ADMIN_ROLES_MANAGE]})
    admin.put(f"/api/admin/users/{app.user_id('dev.user')}/roles", {"roleIds": [app.role_id("Staff manager")]})
    mgr = app.client().sign_in("dev.user")
    options = mgr.get("/api/admin/roles/ad-scope-options").json()
    assert [o["dn"] for o in options["userOus"]] == [fd.STAFF]
    assert len(admin.get("/api/admin/roles/ad-scope-options").json()["userOus"]) == 2  # admins still see both
