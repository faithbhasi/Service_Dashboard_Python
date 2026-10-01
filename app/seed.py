"""Default roles and (in Development) the sample sign-in users."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import permissions as P
from .config import Settings
from .db import AppUser, GroupMapping, Role, RolePermission, UserRole
from .logging_setup import get_logger

log = get_logger("seed")

# (name, display name, role name)
DEV_USERS = [
    ("dev.admin", "Dev Admin", P.ADMINS),
    ("dev.auditor", "Dev Auditor", P.AUDITORS),
    ("dev.helpdesk", "Dev Helpdesk", "Helpdesk (sample)"),
    ("dev.user", "Dev User", P.USERS),
    ("dev.noaccess", "Dev No Access", ""),
    ("dev.disabled", "Dev Disabled", P.USERS),
]


def set_permissions(role: Role, permissions) -> None:
    wanted = set(permissions)
    for p in [p for p in role.permissions if p.permission not in wanted]:
        role.permissions.remove(p)
    have = {p.permission for p in role.permissions}
    for w in sorted(wanted - have):
        role.permissions.append(RolePermission(role_id=role.id, permission=w))


def seed(db: Session, settings: Settings) -> None:
    _ensure_default_roles(db)
    _bootstrap_admin_group(db, settings)
    if settings.okta.development_sign_in and settings.is_development:
        _seed_dev_users(db)


def _ensure_default_roles(db: Session) -> None:
    roles = {r.id: r for r in db.scalars(select(Role))}

    def get(rid, name, description, perms) -> Role:
        r = roles.get(str(rid))
        if r is None:
            r = Role(id=str(rid), name=name, description=description, is_system=True)
            db.add(r)
            roles[r.id] = r
            set_permissions(r, perms)
        return r

    admins = get(P.ADMINS_ID, P.ADMINS, "Everything, including access management and settings.", P.ALL_IDS)
    get(P.AUDITORS_ID, P.AUDITORS, "Read access to AD and full access to Activity and Logs. No changes.", P.AUDITOR_PERMISSIONS)
    get(P.USERS_ID, P.USERS, "Only the modules and actions assigned to them.", P.USER_PERMISSIONS)
    set_permissions(admins, P.ALL_IDS)  # Admins always holds every permission, including ones added by later versions
    db.commit()


def _bootstrap_admin_group(db: Session, settings: Settings) -> None:
    """The very first admin has to come from somewhere: if an Okta group is configured and nothing maps to Admins yet, map it.
    Everything after that is managed in the Users and Groups area."""
    group = settings.app.bootstrap_admin_okta_group
    if not group.strip():
        return
    if db.scalar(select(GroupMapping).where(GroupMapping.role_id == str(P.ADMINS_ID))) is not None:
        return
    db.add(GroupMapping(okta_group=group.strip(), role_id=str(P.ADMINS_ID)))
    db.commit()
    log.warning("Mapped Okta group %s to the Admins role (bootstrap).", group)


def _seed_dev_users(db: Session) -> None:
    helpdesk = db.scalar(select(Role).where(Role.name == "Helpdesk (sample)"))
    if helpdesk is None:
        helpdesk = Role(name="Helpdesk (sample)", description="Sample custom role for local testing.")
        db.add(helpdesk)
        set_permissions(helpdesk, [
            P.DASHBOARD_READ, P.AD_USERS_READ, P.AD_USERS_UNLOCK, P.AD_USERS_RESET_PASSWORD, P.AD_USERS_GROUPS_ADD,
            P.AD_COMPUTERS_READ, P.AD_GROUPS_READ, P.LOGS_READ_OWN,
        ])
        db.commit()
    role_ids = {r.name: r.id for r in db.scalars(select(Role))}
    for name, display, role_name in DEV_USERS:
        subject = "dev|" + name
        if db.scalar(select(AppUser).where(AppUser.subject == subject)) is not None:
            continue
        user = AppUser(subject=subject, display_name=display, email=f"{name}@example.invalid", is_enabled=name != "dev.disabled")
        if role_name:
            user.user_roles.append(UserRole(role_id=role_ids[role_name]))
        db.add(user)
    db.commit()
