"""Creates or updates the app user at sign-in and writes the session."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import AuditEntry, AuditService
from .db import AppUser, AuditCategory, AuditResult
from .request_context import request_info
from .util import utcnow

SIGN_IN_CLAIM = "sd_signin"
ACTIVE_CLAIM = "sd_active"
UID = "uid"


@dataclass
class SignInOutcome:
    user: AppUser | None
    denial_reason: str | None = None


class UserProvisioning:
    def __init__(self, db: Session, audit: AuditService):
        self.db = db
        self.audit = audit

    def sign_in(self, subject: str, email: str | None, name: str | None, okta_groups: list[str]) -> SignInOutcome:
        user = self.db.scalar(select(AppUser).where(AppUser.subject == subject))
        if user is None:
            user = AppUser(subject=subject, email=email or "", display_name=name or email or subject, is_enabled=True)
            self.db.add(user)
        else:
            if email and email.strip():
                user.email = email
            if name and name.strip():
                user.display_name = name
        seen: dict[str, str] = {}
        for g in okta_groups:
            seen.setdefault(g.lower(), g)
        user.okta_groups_json = json.dumps(list(seen.values()))

        if not user.is_enabled:
            self.db.commit()
            self.audit.write(AuditEntry(
                action="logon.denied", category=AuditCategory.Logon, user_id=user.id, user_name=user.display_name,
                result=AuditResult.DENIED, error="Access to this application is disabled for this user"))
            return SignInOutcome(None, "disabled")

        user.last_sign_in_utc = utcnow()
        self.db.commit()
        self.audit.write(AuditEntry(action="logon.signin", category=AuditCategory.Logon, user_id=user.id, user_name=user.display_name))
        return SignInOutcome(user)

    @staticmethod
    def start_session(session: dict, user: AppUser, **extra) -> None:
        """Replaces the session contents with a fresh signed-in session (the caller also rotates the session id)."""
        now = int(time.time())
        session.clear()  # a new anti-forgery token is issued after sign-in
        session.update({UID: user.id, "name": user.display_name, "email": user.email, SIGN_IN_CLAIM: now, ACTIVE_CLAIM: now, **extra})
        info = request_info()
        if info:
            info.user_id, info.user_name = user.id, user.display_name
