from urllib.parse import quote


def categories(body) -> list[str]:
    return [c["key"] for m in body["modules"] for c in m["categories"]]


def test_search_needs_two_characters_and_a_session(shared_app):
    anon = shared_app.client()
    assert anon.get("/api/search?q=alice").status_code == 401
    c = shared_app.client().sign_in("dev.admin")
    assert c.get("/api/search?q=a").status_code == 400
    assert c.get("/api/search").status_code == 400


def test_search_returns_users_computers_and_groups_capped_at_five_each_with_a_total(shared_app):
    c = shared_app.client().sign_in("dev.admin")
    body = c.get("/api/search?q=an").json()
    assert categories(body) == ["users", "computers", "groups"]
    for cat in body["modules"][0]["categories"]:
        assert len(cat["items"]) <= 5
    users = body["modules"][0]["categories"][0]
    assert users["total"] > 5
    assert users["seeAllRoute"].startswith("/ad/users?q=")
    assert users["items"][0]["route"].startswith("/ad/users/")


def test_only_categories_the_user_can_read_are_searched(shared_app):
    c = shared_app.client().sign_in("dev.helpdesk")  # users, computers, groups read
    assert categories(c.get("/api/search?q=an").json()) == ["users", "computers", "groups"]

    admin = shared_app.client().sign_in("dev.admin")
    role = admin.post("/api/admin/roles", {"name": "Groups only", "permissions": ["ad.groups.read"]}).json()
    admin.put(f"/api/admin/users/{shared_app.user_id('dev.user')}/roles", {"roleIds": [role["id"]]})
    limited = shared_app.client().sign_in("dev.user")
    assert categories(limited.get("/api/search?q=gg").json()) == ["groups"]

    none = shared_app.client().sign_in("dev.noaccess")
    assert len(none.get("/api/search?q=alice").json()["modules"]) == 0


def test_ldap_metacharacters_in_the_search_box_are_harmless(shared_app):
    c = shared_app.client().sign_in("dev.admin")
    res = c.get("/api/search?q=" + quote("*)(objectClass=*", safe=""))
    assert res.status_code == 200
    assert all(cat["total"] == 0 for cat in res.json()["modules"][0]["categories"])  # matched literally, so nothing


def test_search_results_say_when_an_account_is_disabled_or_locked(shared_app):
    c = shared_app.client().sign_in("dev.admin")
    body = c.get("/api/search?q=erin.disabled").json()
    item = body["modules"][0]["categories"][0]["items"][0]
    assert "Disabled" in item["tags"]


def test_dashboard_shows_only_the_cards_the_user_may_read(app):
    shared_app = app
    def keys(b): return [x["key"] for x in b["cards"]]

    everything = ["lockedUsers", "disabledUsers", "expiredUsers", "disabledComputers", "actionsToday", "failedToday"]
    admin = shared_app.client().sign_in("dev.admin")
    assert keys(admin.get("/api/dashboard").json()) == everything

    user = shared_app.client().sign_in("dev.helpdesk")
    assert keys(user.get("/api/dashboard").json()) == everything

    basic = shared_app.client().sign_in("dev.user")  # dashboard.read + logs.read.own only
    basic_body = basic.get("/api/dashboard").json()
    assert keys(basic_body) == ["actionsToday", "failedToday"]
    assert "Your" in basic_body["cards"][0]["title"]

    no_dash = shared_app.client().sign_in("dev.noaccess")
    assert no_dash.get("/api/dashboard").status_code == 403


def test_dashboard_counts_match_the_directory_and_link_to_filtered_lists(shared_app):
    c = shared_app.client().sign_in("dev.admin")
    cards = {x["key"]: x for x in c.get("/api/dashboard").json()["cards"]}
    locked = c.get("/api/modules/ad/users?filter=Locked&pageSize=1").json()
    assert locked["total"] == cards["lockedUsers"]["count"]
    assert cards["lockedUsers"]["route"] == "/ad/users?filter=Locked"
    assert "updatedUtc" in cards["lockedUsers"]
