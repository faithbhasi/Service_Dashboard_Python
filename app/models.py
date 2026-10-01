"""Plain data types shared across services (the table definitions live in db.py)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class AdScope:
    """What a role may manage in Active Directory, inside the global allowlists on Settings > AD Integration (which stay the ceiling).

    A None list means "no extra limit from this role"; an empty list means "nothing". Entries are distinguished names.
    """

    user_ous: list[str] | None = None  # OUs whose users this role may change
    computer_ous: list[str] | None = None
    groups: list[str] | None = None  # groups users may be added to or removed from by this role

    @property
    def is_unrestricted(self) -> bool:
        return self.user_ous is None and self.computer_ous is None and self.groups is None

    @staticmethod
    def parse(raw: str | None) -> AdScope:
        if not raw or not raw.strip():
            return AdScope()
        try:
            d = json.loads(raw)
            return AdScope.from_dict(d)
        except (ValueError, TypeError, AttributeError):
            return AdScope()

    @staticmethod
    def from_dict(d: dict | None) -> AdScope:
        d = d or {}

        def lst(v):
            return None if v is None else [str(x) for x in v]

        return AdScope(lst(d.get("userOus")), lst(d.get("computerOus")), lst(d.get("groups")))

    def to_dict(self) -> dict:
        return {"userOus": self.user_ous, "computerOus": self.computer_ous, "groups": self.groups}

    def to_json(self) -> str | None:
        return None if self.is_unrestricted else json.dumps(self.to_dict())


@dataclass(frozen=True)
class AdScopeOption:
    dn: str
    label: str


@dataclass
class AdScopeOptions:
    user_ous: list[AdScopeOption] = field(default_factory=list)
    computer_ous: list[AdScopeOption] = field(default_factory=list)
    groups: list[AdScopeOption] = field(default_factory=list)


@dataclass(frozen=True)
class AdScopeOuNode:
    dn: str
    name: str
    has_children: bool
    selectable: bool
    reason: str | None
