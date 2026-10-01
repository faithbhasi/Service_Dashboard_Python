"""Deterministic seed data for the Fake directory: the same GUIDs on every start so links and tests stay stable."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ...util import utcnow
from . import user_status as us

BASE = "DC=fake,DC=local"
CORP = "OU=Corp," + BASE
STAFF = "OU=Staff," + CORP
CONTRACTORS = "OU=Contractors," + CORP
WORKSTATIONS = "OU=Workstations," + CORP
LAPTOPS = "OU=Laptops," + CORP
SERVERS = "OU=Servers," + CORP
GROUPS_OU = "OU=Groups," + CORP
SERVICE_ACCOUNTS = "OU=Service Accounts," + CORP
TIER0 = "OU=Tier 0," + CORP
DOMAIN_CONTROLLERS = "OU=Domain Controllers," + BASE
BUILTIN = "CN=Builtin," + BASE
USERS_CONTAINER = "CN=Users," + BASE

OU_LIST = [
    CORP, STAFF, "OU=Sales," + STAFF, "OU=Engineering," + STAFF, "OU=Finance," + STAFF, CONTRACTORS,
    WORKSTATIONS, LAPTOPS, SERVERS, GROUPS_OU, SERVICE_ACCOUNTS, TIER0, DOMAIN_CONTROLLERS,
]


def fake_id(key: str) -> uuid.UUID:
    """Same layout as .NET `new Guid(MD5.HashData(...))` (first three fields little-endian)."""
    return uuid.UUID(bytes_le=hashlib.md5(("service-dashboard-fake:" + key).encode("utf-8")).digest())


@dataclass
class FakeUser:
    id: uuid.UUID
    sam: str
    given: str | None = None
    surname: str | None = None
    display: str | None = None
    email: str | None = None
    employee: str | None = None
    title: str | None = None
    department: str | None = None
    office: str | None = None
    phone: str | None = None
    mobile: str | None = None
    description: str | None = None
    manager: uuid.UUID | None = None
    ou: str = ""
    uac: int = us.NORMAL_ACCOUNT
    locked_out: bool = False
    locked_at: datetime | None = None  # when the account locked out (hourly chart); cleared by an unlock
    account_expires: int = 0
    pwd_last_set: int = 0
    pso: str | None = None
    pso_max_age_days: int = 0
    last_logon: datetime | None = None
    created: datetime | None = None
    changed: datetime | None = None
    admin_count: bool = False

    @property
    def dn(self) -> str:
        return f"CN={self.display or self.sam},{self.ou}"


@dataclass
class FakeComputer:
    id: uuid.UUID
    name: str
    os: str | None = None
    os_version: str | None = None
    disabled: bool = False
    ou: str = ""
    last_logon: datetime | None = None
    pwd_last_set: datetime | None = None
    managed_by: uuid.UUID | None = None
    description: str | None = None
    created: datetime | None = None
    changed: datetime | None = None

    @property
    def dn(self) -> str:
        return f"CN={self.name},{self.ou}"


@dataclass
class FakeGroup:
    id: uuid.UUID
    name: str
    description: str | None = None
    scope: str = "Global"
    type: str = "Security"
    ou: str = ""
    managed_by: uuid.UUID | None = None
    admin_count: bool = False
    token: int = 0

    @property
    def dn(self) -> str:
        return f"CN={self.name},{self.ou}"


FIRST = ["Alex", "Blake", "Casey", "Dana", "Eli", "Fran", "Gio", "Hana", "Ivan", "Jules", "Kira", "Leo", "Maya", "Noor", "Omar", "Pia", "Quinn", "Ravi", "Sara", "Tomas"]
LAST = ["Adams", "Baker", "Chen", "Diaz", "Evans", "Fox", "Green", "Hughes", "Iyer", "Jones", "Khan", "Lopez", "Miller", "Nguyen", "Owens", "Patel", "Quinn", "Reed", "Singh", "Turner"]
DEPARTMENTS = ["Sales", "Engineering", "Finance"]
OFFICES = ["London", "Manchester", "Leeds", "Remote"]


@dataclass
class FakeDirectoryData:
    users: list[FakeUser] = field(default_factory=list)
    computers: list[FakeComputer] = field(default_factory=list)
    groups: list[FakeGroup] = field(default_factory=list)
    members: dict[uuid.UUID, set[uuid.UUID]] = field(default_factory=dict)  # group id -> ids of direct members
    denied_targets: set[uuid.UUID] = field(default_factory=set)  # targets the simulated service account has no rights on

    def group(self, name: str) -> FakeGroup:
        return next(g for g in self.groups if g.name == name)

    def user(self, sam: str) -> FakeUser:
        return next(u for u in self.users if u.sam == sam)

    def add_member(self, group: str, member: uuid.UUID) -> None:
        self.members.setdefault(self.group(group).id, set()).add(member)


def seed() -> FakeDirectoryData:
    d = FakeDirectoryData()
    now = utcnow()
    ft = us.to_filetime

    def U(sam: str, given: str, sur: str, ou: str, **o) -> FakeUser:
        locked = bool(o.get("locked"))
        u = FakeUser(
            id=fake_id("user:" + sam), sam=sam, given=given, surname=sur, display=f"{given} {sur}",
            email=None if o.get("noemail") else f"{sam}@fake.example",
            employee=o.get("emp"), title=o.get("title"), department=o.get("dept"), office=o.get("office"),
            phone=o.get("phone"), mobile=o.get("mobile"), description=o.get("desc"),
            manager=o.get("mgr"), ou=ou, uac=us.NORMAL_ACCOUNT | o.get("uac", 0), locked_out=locked,
            locked_at=now - timedelta(minutes=20 + sum(ord(ch) for ch in sam) % 1300) if locked else None,
            account_expires=o.get("expires", 0),
            pwd_last_set=o["pwdset"] if "pwdset" in o else ft(now - timedelta(days=20)),
            pso=o.get("pso"), pso_max_age_days=o.get("psoAge", 0),
            last_logon=o["lastlogon"] if "lastlogon" in o else now - timedelta(days=2),
            created=now - timedelta(days=400), changed=now - timedelta(days=5), admin_count=bool(o.get("admincount")),
        )
        d.users.append(u)
        return u

    # ---- named users covering every state
    carol = U("carol.white", "Carol", "White", STAFF, title="Director of Engineering", dept="Engineering", office="London", phone="+44 20 5550 0101", mobile="+44 7700 900101", emp="E1001")
    bob = U("bob.jones", "Bob", "Jones", "OU=Engineering," + STAFF, title="Engineering Manager", dept="Engineering", office="London", phone="+44 20 5550 0102", mobile="+44 7700 900102", emp="E1002", mgr=carol.id)
    U("alice.smith", "Alice", "Smith", "OU=Engineering," + STAFF, title="Software Engineer", dept="Engineering", office="London", phone="+44 20 5550 0103", mobile="+44 7700 900103", emp="E1003", mgr=bob.id, desc="Platform team")
    U("dave.locked", "Dave", "Locked", "OU=Sales," + STAFF, title="Account Executive", dept="Sales", office="Manchester", emp="E1004", mgr=carol.id, locked=True)
    U("erin.disabled", "Erin", "Disabled", "OU=Sales," + STAFF, title="Sales Analyst", dept="Sales", office="Manchester", emp="E1005", uac=us.ACCOUNT_DISABLE, lastlogon=now - timedelta(days=90))
    U("frank.expired", "Frank", "Expired", CONTRACTORS, title="Contractor", dept="Engineering", office="Remote", emp="C2001", expires=ft(now - timedelta(days=10)))
    U("gina.expiring", "Gina", "Expiring", CONTRACTORS, title="Contractor", dept="Finance", office="Leeds", emp="C2002", expires=ft(now + timedelta(days=30)))
    U("grace.pwdexpired", "Grace", "Pwdexpired", "OU=Finance," + STAFF, title="Accountant", dept="Finance", office="Leeds", emp="E1006", pwdset=ft(now - timedelta(days=200)))
    U("henry.neverexpires", "Henry", "Neverexpires", "OU=Finance," + STAFF, title="Finance Systems Owner", dept="Finance", office="Leeds", emp="E1007", uac=us.DONT_EXPIRE_PASSWORD, pwdset=ft(now - timedelta(days=700)))
    U("irene.mustchange", "Irene", "Mustchange", "OU=Sales," + STAFF, title="New Starter", dept="Sales", office="London", emp="E1008", pwdset=0, lastlogon=None)
    U("jack.pso", "Jack", "Pso", "OU=Engineering," + STAFF, title="Site Reliability Engineer", dept="Engineering", office="Remote", emp="E1009", mgr=bob.id, pso="Privileged-Users-PSO", psoAge=30, pwdset=ft(now - timedelta(days=12)))
    U("kim.sparse", "Kim", "Sparse", CONTRACTORS, noemail=True)
    U("svc.noperm", "Svc", "Noperm", CONTRACTORS, title="Simulated: service account lacks rights", dept="Engineering", emp="C2003")
    U("adm.tier0", "Adm", "Tier0", TIER0, title="Tier 0 administrator", dept="Engineering", emp="A0001", admincount=True)
    U("svc.backup", "Svc", "Backup", SERVICE_ACCOUNTS, title="Backup service account", uac=us.DONT_EXPIRE_PASSWORD)
    d.denied_targets.add(fake_id("user:svc.noperm"))

    # ---- filler users (paging, big group, dashboard counts)
    for i in range(1, 601):
        given = FIRST[i % len(FIRST)]
        sur = LAST[(i // len(FIRST) + i) % len(LAST)]
        sam = f"{given.lower()}.{sur.lower()}{i:03d}"
        dept = DEPARTMENTS[i % 3]
        ou = {"Sales": "OU=Sales," + STAFF, "Engineering": "OU=Engineering," + STAFF}.get(dept, "OU=Finance," + STAFF)
        o: dict = {
            "title": "Engineer" if dept == "Engineering" else "Sales Associate" if dept == "Sales" else "Finance Analyst",
            "dept": dept, "office": OFFICES[i % 4], "emp": f"E{3000 + i}", "mgr": bob.id if i % 2 == 0 else carol.id,
        }
        if i % 37 == 0:
            o["locked"] = True
        if i % 23 == 0:
            o["uac"] = us.ACCOUNT_DISABLE
        if i % 41 == 0:
            o["expires"] = ft(now - timedelta(days=3))
        if i % 53 == 0:
            o["pwdset"] = ft(now - timedelta(days=150))
        U(sam, given, sur, ou, **o)

    # ---- computers
    def C(name: str, ou: str, os: str, ver: str, disabled: bool = False, managed_by=None, desc=None, last_logon=None) -> FakeComputer:
        c = FakeComputer(
            id=fake_id("computer:" + name), name=name, ou=ou, os=os, os_version=ver, disabled=disabled, managed_by=managed_by,
            description=desc, last_logon=last_logon or now - timedelta(days=1), pwd_last_set=now - timedelta(days=14),
            created=now - timedelta(days=300), changed=now - timedelta(days=3),
        )
        d.computers.append(c)
        return c

    C("DC01", DOMAIN_CONTROLLERS, "Windows Server 2022 Datacenter", "10.0 (20348)")
    C("SRV-APP01", SERVERS, "Windows Server 2022 Standard", "10.0 (20348)", managed_by=bob.id, desc="CRM application server")
    C("SRV-FILE01", SERVERS, "Windows Server 2019 Standard", "10.0 (17763)", managed_by=fake_id("group:GG-Helpdesk"))
    C("WS-NOPERM", WORKSTATIONS, "Windows 11 Pro", "10.0 (22631)", desc="Simulated: service account lacks rights")
    d.denied_targets.add(fake_id("computer:WS-NOPERM"))
    C("LT-OLD01", LAPTOPS, "Windows 10 Enterprise", "10.0 (19045)", disabled=True, last_logon=now - timedelta(days=200))
    C("LT-OLD02", LAPTOPS, "Windows 10 Pro", "10.0 (19044)", disabled=True, last_logon=now - timedelta(days=320))
    for i in range(1, 61):
        laptop = i % 3 == 0
        owner = d.users[(i * 7) % 40 + 3]
        C(f"{'LT' if laptop else 'WS'}-{i:03d}", LAPTOPS if laptop else WORKSTATIONS,
          "Windows 10 Enterprise" if i % 5 == 0 else "Windows 11 Enterprise", "10.0 (19045)" if i % 5 == 0 else "10.0 (22631)",
          disabled=i % 19 == 0, managed_by=owner.id if i % 4 == 0 else None, desc=f"Last user: {owner.sam}")

    # ---- groups
    def G(name: str, ou: str, scope: str = "Global", type: str = "Security", admin: bool = False, desc=None, managed_by=None, token: int = 0) -> FakeGroup:
        g = FakeGroup(id=fake_id("group:" + name), name=name, ou=ou, scope=scope, type=type, admin_count=admin, description=desc,
                      managed_by=managed_by, token=token or 1100 + len(d.groups))
        d.groups.append(g)
        return g

    G("Domain Users", USERS_CONTAINER, desc="All domain users", token=513)
    G("Domain Computers", USERS_CONTAINER, desc="All workstations and servers", token=515)
    G("Domain Admins", USERS_CONTAINER, admin=True, desc="Designated administrators of the domain", token=512)
    G("Enterprise Admins", USERS_CONTAINER, "Universal", admin=True, desc="Designated administrators of the enterprise")
    G("Schema Admins", USERS_CONTAINER, "Universal", admin=True, desc="Designated administrators of the schema")
    G("Administrators", BUILTIN, "DomainLocal", admin=True, desc="Administrators have complete and unrestricted access")
    G("Account Operators", BUILTIN, "DomainLocal", admin=True, desc="Members can administer domain user and group accounts")
    G("Backup Operators", BUILTIN, "DomainLocal", admin=True, desc="Backup Operators can override security restrictions")
    G("Server Operators", BUILTIN, "DomainLocal", admin=True, desc="Members can administer domain servers")
    G("Print Operators", BUILTIN, "DomainLocal", admin=True, desc="Members can administer domain printers")
    G("Custom-Protected-Admins", GROUPS_OU, admin=True, desc="Custom group with adminCount=1 (protected by SDProp)")
    G("GG-Sales", GROUPS_OU, desc="Sales department", managed_by=carol.id)
    G("GG-Engineering", GROUPS_OU, desc="Engineering department", managed_by=bob.id)
    G("GG-Finance", GROUPS_OU, desc="Finance department")
    G("GG-All-Staff", GROUPS_OU, desc="Everyone on the staff payroll (nested: departments)")
    G("GG-Intranet", GROUPS_OU, desc="Intranet access (nested: All Staff)")
    G("GG-VPN-Users", GROUPS_OU, desc="Allowed to use the VPN")
    G("GG-Helpdesk", GROUPS_OU, desc="Helpdesk operators")
    G("GG-Finance-Share-RW", GROUPS_OU, "DomainLocal", desc="Read/write on the finance share")
    G("GG-Finance-Share-RO", GROUPS_OU, "DomainLocal", desc="Read-only on the finance share")
    G("APP-CRM-Users", GROUPS_OU, "Universal", desc="Users of the CRM application")
    G("DL-Announcements", GROUPS_OU, "Universal", "Distribution", desc="Company announcements mailing list")
    G("GG-All-Company", GROUPS_OU, desc="Very large group used to test member search and paging")

    # ---- memberships
    for u in d.users:
        if u.ou not in (TIER0, SERVICE_ACCOUNTS):
            d.add_member("GG-All-Company", u.id)
    for c in d.computers[:40]:
        d.add_member("GG-All-Company", c.id)
    for u in d.users:
        d.add_member("Domain Admins" if u.ou == TIER0 else "Domain Users", u.id)
    for c in d.computers:
        d.add_member("Domain Computers", c.id)
    for u in d.users:
        if u.department == "Engineering":
            d.add_member("GG-Engineering", u.id)
        if u.department == "Sales":
            d.add_member("GG-Sales", u.id)
        if u.department == "Finance" and u.ou.startswith("OU=Finance"):
            d.add_member("GG-Finance", u.id)
    d.add_member("GG-All-Staff", d.group("GG-Sales").id)
    d.add_member("GG-All-Staff", d.group("GG-Engineering").id)
    d.add_member("GG-All-Staff", d.group("GG-Finance").id)
    d.add_member("GG-Intranet", d.group("GG-All-Staff").id)
    d.add_member("GG-Finance-Share-RW", d.group("GG-Finance").id)
    for sam in ("alice.smith", "bob.jones", "jack.pso"):
        d.add_member("GG-VPN-Users", d.user(sam).id)
    d.add_member("APP-CRM-Users", d.user("dave.locked").id)
    d.add_member("GG-Helpdesk", d.user("carol.white").id)
    d.add_member("Domain Admins", d.user("carol.white").id)  # an ordinary user who is also in a protected group
    d.add_member("Administrators", d.group("Domain Admins").id)
    d.add_member("Custom-Protected-Admins", d.user("jack.pso").id)
    return d
