"""Every permission in the application, the combined 'any of' policies, and the default roles."""
from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class PermissionInfo:
    id: str
    group: str
    description: str


DASHBOARD_READ = "dashboard.read"
AD_USERS_READ = "ad.users.read"
AD_USERS_RESET_PASSWORD = "ad.users.resetPassword"
AD_USERS_UNLOCK = "ad.users.unlock"
AD_USERS_ENABLE = "ad.users.enable"
AD_USERS_DISABLE = "ad.users.disable"
AD_USERS_MOVE = "ad.users.move"
AD_USERS_GROUPS_ADD = "ad.users.groups.add"
AD_USERS_GROUPS_REMOVE = "ad.users.groups.remove"
AD_COMPUTERS_READ = "ad.computers.read"
AD_COMPUTERS_ENABLE = "ad.computers.enable"
AD_COMPUTERS_DISABLE = "ad.computers.disable"
AD_COMPUTERS_MOVE = "ad.computers.move"
AD_GROUPS_READ = "ad.groups.read"
AD_GROUPS_MEMBER_EXPORT = "ad.groups.member.export"
LOGS_READ_OWN = "logs.read.own"
LOGS_READ = "logs.read"
LOGS_EXPORT = "logs.export"
ADMIN_USERS_MANAGE = "admin.users.manage"
ADMIN_ROLES_MANAGE = "admin.roles.manage"
SETTINGS_READ = "settings.read"
SETTINGS_MANAGE = "settings.manage"
SETTINGS_PERSONALIZATION_MANAGE = "settings.personalization.manage"

ALL: list[PermissionInfo] = [
    PermissionInfo(DASHBOARD_READ, "Home", "View the Home dashboard cards."),
    PermissionInfo(AD_USERS_READ, "Active Directory - Users", "Search and view AD users and their memberships."),
    PermissionInfo(AD_USERS_RESET_PASSWORD, "Active Directory - Users", "Reset an AD user's password."),
    PermissionInfo(AD_USERS_UNLOCK, "Active Directory - Users", "Unlock a locked AD user account."),
    PermissionInfo(AD_USERS_ENABLE, "Active Directory - Users", "Enable a disabled AD user account."),
    PermissionInfo(AD_USERS_DISABLE, "Active Directory - Users", "Disable an AD user account."),
    PermissionInfo(AD_USERS_MOVE, "Active Directory - Users", "Move an AD user to another allowed OU."),
    PermissionInfo(AD_USERS_GROUPS_ADD, "Active Directory - Users", "Add an AD user to manageable groups."),
    PermissionInfo(AD_USERS_GROUPS_REMOVE, "Active Directory - Users", "Remove an AD user from manageable groups."),
    PermissionInfo(AD_COMPUTERS_READ, "Active Directory - Computers", "Search and view AD computers."),
    PermissionInfo(AD_COMPUTERS_ENABLE, "Active Directory - Computers", "Enable a disabled AD computer account."),
    PermissionInfo(AD_COMPUTERS_DISABLE, "Active Directory - Computers", "Disable an AD computer account."),
    PermissionInfo(AD_COMPUTERS_MOVE, "Active Directory - Computers", "Move an AD computer to another allowed OU."),
    PermissionInfo(AD_GROUPS_READ, "Active Directory - Groups", "View AD groups and their members."),
    PermissionInfo(AD_GROUPS_MEMBER_EXPORT, "Active Directory - Groups", "Export a group's member list to CSV."),
    PermissionInfo(LOGS_READ_OWN, "Activity and Logs", "View only the activity performed by yourself."),
    PermissionInfo(LOGS_READ, "Activity and Logs", "View all activity and logs."),
    PermissionInfo(LOGS_EXPORT, "Activity and Logs", "Export activity and logs to CSV."),
    PermissionInfo(ADMIN_USERS_MANAGE, "Users and Groups", "Manage app users and Okta group mappings."),
    PermissionInfo(ADMIN_ROLES_MANAGE, "Users and Groups", "Create, clone and edit roles."),
    PermissionInfo(SETTINGS_READ, "Settings", "View settings."),
    PermissionInfo(SETTINGS_MANAGE, "Settings", "Change settings."),
    PermissionInfo(SETTINGS_PERSONALIZATION_MANAGE, "Settings", "Change logo, colours and product name."),
]
ALL_IDS: frozenset[str] = frozenset(p.id for p in ALL)

# Policies that accept any one of several permissions.
LOGS_ACCESS = (LOGS_READ, LOGS_READ_OWN)
ADMIN_ACCESS = (ADMIN_USERS_MANAGE, ADMIN_ROLES_MANAGE)
SETTINGS_ACCESS = (SETTINGS_READ, SETTINGS_MANAGE, SETTINGS_PERSONALIZATION_MANAGE)
# Browsing the OU tree: needed by the Move OU tabs and by the allowlist editor in Settings.
AD_OU_BROWSE = (AD_USERS_MOVE, AD_COMPUTERS_MOVE, SETTINGS_MANAGE)

ADMINS_ID = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
AUDITORS_ID = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
USERS_ID = uuid.UUID("00000000-0000-0000-0000-0000000000a3")

ADMINS = "Admins"
AUDITORS = "Auditors and Security"
USERS = "Users"

AUDITOR_PERMISSIONS = [
    DASHBOARD_READ, AD_USERS_READ, AD_COMPUTERS_READ, AD_GROUPS_READ, AD_GROUPS_MEMBER_EXPORT, LOGS_READ, LOGS_EXPORT,
]
# "Users: only the modules and actions assigned to them" - so the default is the bare minimum.
USER_PERMISSIONS = [DASHBOARD_READ, LOGS_READ_OWN]

# Which permissions open each front-end page (any one is enough). Mirrors the navigation.
PAGE_ACCESS: dict[str, tuple[str, ...]] = {
    "home": (),
    "ad.users": (AD_USERS_READ,),
    "ad.computers": (AD_COMPUTERS_READ,),
    "ad.groups": (AD_GROUPS_READ,),
    "logs": (LOGS_READ, LOGS_READ_OWN),
    "admin": (ADMIN_USERS_MANAGE, ADMIN_ROLES_MANAGE),
    "settings": (SETTINGS_READ, SETTINGS_MANAGE, SETTINGS_PERSONALIZATION_MANAGE),
}
