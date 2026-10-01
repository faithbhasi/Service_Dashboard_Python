import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.ad import fake_data as fd
from app.modules.ad import ldap_text as lt
from app.modules.ad import user_status as us
from app.modules.ad.dn import dn_equal, is_under_or_equal, is_valid_dn
from app.modules.ad.fake_provider import FakeDirectoryProvider
from app.modules.ad.provider import (
    ComputerFilter, DirectoryErrors, DirectoryUnavailableError, GroupSearch, MemberKind, MemberSearch, ObjectKind, ReadOptions,
    ResetPasswordOptions, UserFilter, UserSearch,
)

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


class TestUserStatus:
    def test_account_expiry_understands_never_future_and_past(self):
        assert us.account_expiry(0, NOW)[0] == "Never"
        assert us.account_expiry((1 << 63) - 1, NOW)[0] == "Never"
        assert us.account_expiry(us.to_filetime(NOW - timedelta(days=1)), NOW)[0] == "Expired"
        kind, date = us.account_expiry(us.to_filetime(NOW + timedelta(days=5)), NOW)
        assert kind == "Expires"
        assert date == NOW + timedelta(days=5)

    def test_password_status_follows_flags_and_the_computed_expiry_time(self):
        set_ = us.to_filetime(NOW - timedelta(days=10))
        assert us.password(us.DONT_EXPIRE_PASSWORD, 0, set_, None, NOW)[0] == "NeverExpires"
        assert us.password(0, 0, 0, None, NOW)[0] == "MustChange"
        assert us.password(0, us.COMPUTED_PASSWORD_EXPIRED, set_, us.to_filetime(NOW - timedelta(days=1)), NOW)[0] == "Expired"
        status, when = us.password(0, 0, set_, us.to_filetime(NOW + timedelta(days=20)), NOW)
        assert status == "Expires"
        assert when == NOW + timedelta(days=20)
        assert us.password(0, 0, set_, (1 << 63) - 1, NOW)[0] == "NeverExpires"

    def test_an_old_lockout_time_is_not_enough_only_the_computed_bit_counts(self):
        assert us.is_locked_out(0) is False
        assert us.is_locked_out(us.COMPUTED_LOCKOUT) is True

    def test_flags_are_explained_in_plain_language(self):
        flags = us.describe_flags(us.NORMAL_ACCOUNT | us.ACCOUNT_DISABLE | us.DONT_EXPIRE_PASSWORD)
        assert any(f.name == "ACCOUNTDISABLE" and "disabled" in f.meaning for f in flags)
        assert any(f.name == "DONT_EXPIRE_PASSWORD" for f in flags)
        assert not any(f.name == "LOCKOUT" for f in flags)


class TestLdapText:
    @pytest.mark.parametrize("value,expected", [("a*b", "a\\2ab"), ("(x)", "\\28x\\29"), ("back\\slash", "back\\5cslash"), ("nul\0", "nul\\00")])
    def test_filter_values_are_escaped_per_rfc4515(self, value, expected):
        assert lt.escape_filter_value(value) == expected

    def test_injection_attempts_cannot_add_filter_clauses(self):
        attack = "*)(objectClass=*))(|(objectClass=*"
        filters = [
            lt.users_filter(attack, UserFilter.All, "employeeID", datetime.now(UTC)),
            lt.computers_filter(attack, ComputerFilter.All),
            lt.groups_filter(attack),
            lt.members_filter("CN=g,DC=x", attack, None),
        ]
        for f in filters:
            assert "(objectClass=*)" not in f
            assert "\\2a\\29\\28objectClass=\\2a\\29\\29\\28|\\28objectClass=\\2a" in f
            assert f.count("(") == f.count(")")  # the attack text added no parentheses

    def test_a_malicious_group_dn_is_escaped_inside_the_member_filter(self):
        f = lt.members_filter("CN=x)(objectClass=*", None, MemberKind.User)
        assert "(memberOf=CN=x\\29\\28objectClass=\\2a)" in f

    def test_the_employee_id_attribute_setting_cannot_inject_filter_syntax(self):
        f = lt.users_filter("bob", UserFilter.All, "employeeID=*)(objectClass=*", datetime.now(UTC))
        assert "(employeeID=*bob*)" in f
        assert "objectClass=*)" not in f.replace("(objectCategory=person)(objectClass=user)", "")

    def test_guid_filters_use_escaped_bytes(self):
        id_ = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
        assert lt.by_guid(id_) == "(objectGUID=\\44\\33\\22\\11\\66\\55\\88\\77\\99\\aa\\bb\\cc\\dd\\ee\\ff\\00)"

    @pytest.mark.parametrize("dn,valid", [
        ("OU=Staff,OU=Corp,DC=example,DC=test", True), ("CN=Smith\\, John,OU=Staff,DC=example,DC=test", True), ("CN=Hex\\2cName,OU=A,DC=x", True),
        ("", False), ("not a dn", False), ("OU=A,,DC=x", False), ("OU=A\0,DC=x", False), ("OU=A;evil,DC=x", False),
        ("OU=A<x>,DC=x", False), ("OU=trailing\\", False),
    ])
    def test_distinguished_names_are_validated(self, dn, valid):
        assert is_valid_dn(dn) is valid

    def test_a_group_sid_is_the_domain_sid_with_the_rid_appended(self):
        # S-1-5-21-1-2-3 as bytes: revision 1, 4 sub-authorities, authority 5, then 21,1,2,3
        domain = bytes([1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0])
        group = lt.append_rid(domain, 513)
        assert group[1] == 5
        assert len(group) == len(domain) + 4
        assert group[-4:] == bytes([0x01, 0x02, 0x00, 0x00])  # 513 = 0x201, little-endian
        assert lt.escape_bytes(group[:3]) == "\\01\\05\\00"
        with pytest.raises(ValueError):
            lt.append_rid(bytes([1, 2]), 513)

    def test_dn_comparison_ignores_case_and_spacing_and_understands_ancestry(self):
        assert dn_equal("ou=Staff, ou=Corp,dc=X", "OU=Staff,OU=Corp,DC=x")
        assert is_under_or_equal("OU=Sales,OU=Staff,OU=Corp,DC=x", "ou=staff,ou=corp,dc=x")
        assert not is_under_or_equal("OU=Staff,OU=Corp,DC=x", "OU=Sales,OU=Staff,OU=Corp,DC=x")
        assert not is_under_or_equal("OU=Other,DC=x", "OU=Staff,DC=x")


OPTS = ReadOptions()


def users(text=None, f=UserFilter.All, page=1, size=25):
    return UserSearch(text, f, page, size, None, 5000, OPTS)


def user(p, sam):
    return next(u for u in p.search_users(users(sam)).items if u.sam_account_name == sam)


class TestFakeProvider:
    def test_seeded_users_cover_every_account_state(self):
        p = FakeDirectoryProvider()
        assert user(p, "dave.locked").locked_out
        assert not user(p, "erin.disabled").enabled
        assert user(p, "frank.expired").account_expiry == "Expired"
        assert user(p, "gina.expiring").account_expiry == "Expires"
        assert user(p, "grace.pwdexpired").password_status == "Expired"
        assert user(p, "henry.neverexpires").password_status == "NeverExpires"
        assert user(p, "irene.mustchange").password_status == "MustChange"
        assert user(p, "jack.pso").resultant_pso == "Privileged-Users-PSO"
        assert user(p, "alice.smith").resultant_pso is None
        alice = p.get_user(user(p, "alice.smith").id, OPTS)
        assert alice.manager.name == "Bob Jones"
        kim = user(p, "kim.sparse")
        assert kim.email is None and kim.title is None and kim.phone is None

    def test_filters_and_counts_agree(self):
        p = FakeDirectoryProvider()
        locked = p.search_users(users(f=UserFilter.Locked, size=200))
        assert all(u.locked_out for u in locked.items)
        assert locked.total == p.count_users(UserFilter.Locked)
        assert p.count_users(UserFilter.Disabled) > 0
        assert p.count_computers(ComputerFilter.Disabled) >= 2

    def test_user_search_matches_username_upn_name_email_and_employee_id(self):
        p = FakeDirectoryProvider()
        for term in ("alice.smith", "alice.smith@fake.local", "Alice", "Smith", "alice.smith@fake.example", "E1003"):
            assert any(u.sam_account_name == "alice.smith" for u in p.search_users(users(term)).items)

    def test_a_group_with_500_plus_members_is_searched_and_paged_by_the_provider(self):
        p = FakeDirectoryProvider()
        big = p.search_groups(GroupSearch("GG-All-Company", 1, 10, 100)).items[0]
        assert p.get_group(big.id).member_count > 500

        page1 = p.search_group_members(big.id, MemberSearch(None, None, 1, 50))
        assert len(page1.items) == 50  # only one page comes back...
        assert page1.total > 500  # ...while the total reflects the whole group
        page2 = p.search_group_members(big.id, MemberSearch(None, None, 2, 50))
        assert not ({m.id for m in page1.items} & {m.id for m in page2.items})

        filtered = p.search_group_members(big.id, MemberSearch("alex", None, 1, 25))
        assert all("alex" in ((m.name or "") + (m.sam_account_name or "") + (m.email or "")).lower() for m in filtered.items)
        assert 0 < filtered.total < page1.total

        computers = p.search_group_members(big.id, MemberSearch(None, MemberKind.Computer, 1, 100))
        assert all(m.kind == MemberKind.Computer for m in computers.items)
        assert computers.total == 40

    def test_nested_and_primary_memberships_are_reported(self):
        p = FakeDirectoryProvider()
        alice = user(p, "alice.smith")
        m = p.get_memberships(alice.id, ObjectKind.User)
        assert any(g.name == "GG-Engineering" for g in m.direct)
        assert not any(g.name == "Domain Users" for g in m.direct)
        assert m.primary.name == "Domain Users"
        all_staff = next(n for n in m.nested if n.group.name == "GG-All-Staff")
        assert all_staff.via == "GG-Engineering"
        assert any(n.group.name == "GG-Intranet" for n in m.nested)

    def test_dry_run_changes_nothing(self):
        p = FakeDirectoryProvider()
        dave = user(p, "dave.locked")
        r = p.unlock(dave.id, dry_run=True)
        assert r.success and r.dry_run
        assert any(c.field == "Locked out" and c.from_ == "Yes" and c.to == "No" for c in r.changes)
        assert user(p, "dave.locked").locked_out

        assert p.reset_password(dave.id, "Correct-Horse-9", ResetPasswordOptions(True, True), dry_run=True).success
        assert user(p, "dave.locked").password_status != "MustChange"

        assert p.set_enabled(dave.id, ObjectKind.User, False, dry_run=True).success
        assert user(p, "dave.locked").enabled
        assert p.move(dave.id, ObjectKind.User, fd.CONTRACTORS, dry_run=True).success
        assert "OU=Sales" in user(p, "dave.locked").ou

    def test_simulated_failures_behave_like_real_ad(self):
        p = FakeDirectoryProvider()
        alice = user(p, "alice.smith")

        rejected = p.reset_password(alice.id, "weak", ResetPasswordOptions(False, False), dry_run=False)
        assert not rejected.success
        assert rejected.error_code == DirectoryErrors.PASSWORD_REJECTED
        assert "weak" not in rejected.message

        assert p.unlock(uuid.uuid4(), dry_run=False).error_code == DirectoryErrors.NOT_FOUND

        no_perm = user(p, "svc.noperm")
        dry = p.set_enabled(no_perm.id, ObjectKind.User, False, dry_run=True)
        assert not dry.success
        assert dry.error_code == DirectoryErrors.PERMISSION_DENIED

        p.simulation.server_unavailable = True
        with pytest.raises(DirectoryUnavailableError):
            p.search_users(users())

    def test_the_ou_tree_lazy_loads(self):
        p = FakeDirectoryProvider()
        roots = p.browse_ous(None)
        assert any(o.name == "Corp" and o.has_children for o in roots)
        assert any(o.name == "Domain Controllers" for o in roots)
        corp = p.browse_ous(fd.CORP)
        assert any(o.name == "Tier 0" for o in corp)
        assert any(o.name == "Sales" for o in p.search_ous("sales", 10))


class TestDirectoryApi:
    def test_read_endpoints_require_their_permission(self, shared_app):
        noaccess = shared_app.client().sign_in("dev.noaccess")
        for url in ("/api/modules/ad/users", "/api/modules/ad/computers", "/api/modules/ad/groups", f"/api/modules/ad/users/{uuid.uuid4()}",
                    f"/api/modules/ad/groups/{uuid.uuid4()}/members", "/api/modules/ad/ous", "/api/modules/ad/settings"):
            assert noaccess.get(url).status_code == 403

        basic = shared_app.client().sign_in("dev.user")
        assert basic.get("/api/modules/ad/users").status_code == 403

    def test_helpdesk_can_search_and_open_users_and_sees_protected_tags_on_groups(self, shared_app):
        c = shared_app.client().sign_in("dev.helpdesk")
        listing = c.get("/api/modules/ad/users?q=alice.smith").json()
        assert listing["total"] == 1
        id_ = listing["items"][0]["id"]

        detail = c.get(f"/api/modules/ad/users/{id_}").json()
        assert detail["user"]["samAccountName"] == "alice.smith"
        assert detail["ouManageable"] is True

        groups = c.get("/api/modules/ad/groups?q=Domain Admins").json()
        da = next(g for g in groups["items"] if g["name"] == "Domain Admins")
        assert da["isProtected"] is True
        assert da["isManageable"] is False

    def test_directory_outage_returns_a_safe_503_with_a_correlation_id(self, app):
        c = app.client().sign_in("dev.admin")
        app.state.provider.simulation.server_unavailable = True
        res = c.get("/api/modules/ad/users")
        assert res.status_code == 503
        assert "correlationId" in res.text
        assert "Simulated" not in res.text  # technical detail stays in the logs

    def test_group_member_export_needs_its_own_permission_is_audited_and_protects_against_formulas(self, app):
        helpdesk = app.client().sign_in("dev.helpdesk")
        big = helpdesk.get("/api/modules/ad/groups?q=GG-All-Company").json()["items"][0]["id"]
        assert helpdesk.get(f"/api/modules/ad/groups/{big}/members/export").status_code == 403

        auditor = app.client().sign_in("dev.auditor")
        assert auditor.get(f"/api/modules/ad/groups/{big}/members/export?q=alex").status_code == 200  # part of the default Auditors role

        admin = app.client().sign_in("dev.admin")
        ok = admin.get(f"/api/modules/ad/groups/{big}/members/export?q=alex")
        assert ok.status_code == 200
        assert ok.text.startswith("﻿Name,Username,Email,Type,Enabled,Distinguished name")
        assert any(a.action == "ad.groups.member.export" and a.result == "Success" for a in app.audit())
