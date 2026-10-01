from __future__ import annotations

from dataclasses import dataclass, field
import re

from .access import RoleRef
from .models import AdScope


@dataclass
class CurrentUserInfo:
    id: str
    subject: str
    display_name: str
    email: str
    is_enabled: bool
    theme_preference: str
    nav_collapsed: bool
    roles: list[RoleRef]
    permissions: set[str]
    ad_scope: AdScope = field(default_factory=AdScope)

    @property
    def has_access(self) -> bool:
        return len(self.roles) > 0

    def has(self, permission: str) -> bool:
        return self.is_enabled and permission in self.permissions

    def has_any(self, *permissions: str) -> bool:
        return self.is_enabled and any(p in self.permissions for p in permissions)

    @property
    def initials(self) -> str:
        parts = [p for p in re.split(r"[ .@]", self.display_name) if p]
        if not parts:
            return "?"
        if len(parts) == 1:
            return parts[0][0].upper()
        return (parts[0][0] + parts[-1][0]).upper()
