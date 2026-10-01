"""Runtime AD settings edited on Settings > AD Integration. Stored in SQLite under the key "ad"."""
from __future__ import annotations

from dataclasses import dataclass, field

from ...settings_service import SettingKeys, SettingsService
from .provider import DirectoryProvider, ReadOptions


def _str_list(v) -> list[str]:
    return [x if isinstance(x, str) else str(x) for x in v] if isinstance(v, list) else []


@dataclass
class AdSettings:
    # OUs (DNs) whose users may be changed or moved. Empty means nothing is manageable.
    manageable_user_ous: list[str] = field(default_factory=list)
    manageable_computer_ous: list[str] = field(default_factory=list)
    # OUs that are never manageable, even if they sit under an allowed OU.
    protected_ous: list[str] = field(default_factory=list)
    # Groups (DNs) that users may be added to or removed from.
    manageable_groups: list[str] = field(default_factory=list)
    # Extra protected groups (DN or name), on top of the built-in list and adminCount=1.
    protected_groups: list[str] = field(default_factory=list)
    employee_id_attribute: str = "employeeID"
    # Attribute that holds a computer's last logged-in user (for example written by a logon script). Empty = not available.
    computer_last_user_attribute: str | None = None
    search_result_limit: int = 1000

    @property
    def read_options(self) -> ReadOptions:
        last = self.computer_last_user_attribute
        return ReadOptions(self.employee_id_attribute, None if not last or not last.strip() else last)

    def to_dict(self) -> dict:
        return {
            "manageableUserOus": self.manageable_user_ous, "manageableComputerOus": self.manageable_computer_ous,
            "protectedOus": self.protected_ous, "manageableGroups": self.manageable_groups, "protectedGroups": self.protected_groups,
            "employeeIdAttribute": self.employee_id_attribute, "computerLastUserAttribute": self.computer_last_user_attribute,
            "searchResultLimit": self.search_result_limit,
        }

    @staticmethod
    def from_dict(d: dict | None) -> AdSettings:
        d = d or {}
        last = d.get("computerLastUserAttribute")
        limit = d.get("searchResultLimit", 1000)
        return AdSettings(
            _str_list(d.get("manageableUserOus")), _str_list(d.get("manageableComputerOus")), _str_list(d.get("protectedOus")),
            _str_list(d.get("manageableGroups")), _str_list(d.get("protectedGroups")),
            d.get("employeeIdAttribute") if isinstance(d.get("employeeIdAttribute"), str) else "employeeID",
            last if isinstance(last, str) else None,
            limit if isinstance(limit, int) and not isinstance(limit, bool) else 1000,
        )


class AdSettingsService:
    def __init__(self, settings: SettingsService, provider: DirectoryProvider):
        self.settings = settings
        self.provider = provider

    def _defaults(self) -> AdSettings:
        s = AdSettings()
        d = self.provider.suggested_defaults
        if d is not None:
            s.manageable_user_ous = list(d.user_ous)
            s.manageable_computer_ous = list(d.computer_ous)
            s.manageable_groups = list(d.manageable_groups)
            s.protected_groups = list(d.protected_groups)
            s.computer_last_user_attribute = "description"
        return s

    def get(self) -> AdSettings:
        return self.settings.get_doc(SettingKeys.ACTIVE_DIRECTORY, AdSettings.from_dict, self._defaults)

    def save(self, value: AdSettings, by: str | None) -> tuple[str, str]:
        return self.settings.save_doc(SettingKeys.ACTIVE_DIRECTORY, value, by, AdSettings.from_dict, self._defaults)
