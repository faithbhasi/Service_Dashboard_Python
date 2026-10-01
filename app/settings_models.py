"""The runtime settings documents (stored as JSON in SQLite) and their defaults. JSON uses camelCase, like the front end."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import permissions as P


# ------------------------------------------------------------------------------------------------ general + banner

@dataclass
class BannerSettings:
    enabled: bool = False
    type: str = "Information"  # Information, Warning or Maintenance
    text: str = ""
    start_local: str | None = None  # wall-clock time in the configured zone, "yyyy-MM-ddTHH:mm"
    end_local: str | None = None

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "type": self.type, "text": self.text, "startLocal": self.start_local, "endLocal": self.end_local}

    @staticmethod
    def from_dict(d: dict | None) -> BannerSettings:
        d = d or {}
        return BannerSettings(bool(d.get("enabled", False)), d.get("type") or "Information", d.get("text") or "", d.get("startLocal"), d.get("endLocal"))


@dataclass
class GeneralSettings:
    product_name: str = ""
    environment_label: str = ""
    # null only while binding a request that did not send it (an older client); everything stored or returned is a string.
    environment_label_color: str | None = None
    time_zone: str = "UTC"
    date_format: str = "yyyy-MM-dd"
    support_contact: str = ""
    idle_timeout_minutes: int = 30
    absolute_timeout_minutes: int = 480
    banner: BannerSettings = field(default_factory=BannerSettings)

    def to_dict(self) -> dict:
        return {
            "productName": self.product_name, "environmentLabel": self.environment_label,
            "environmentLabelColor": self.environment_label_color if self.environment_label_color is not None else "",
            "timeZone": self.time_zone, "dateFormat": self.date_format, "supportContact": self.support_contact,
            "idleTimeoutMinutes": self.idle_timeout_minutes, "absoluteTimeoutMinutes": self.absolute_timeout_minutes,
            "banner": self.banner.to_dict(),
        }

    def to_dict_without_banner(self) -> dict:
        d = self.to_dict()
        d.pop("banner")
        return d

    @staticmethod
    def from_dict(d: dict | None) -> GeneralSettings:
        d = d or {}
        return GeneralSettings(
            product_name=d.get("productName") or "", environment_label=d.get("environmentLabel") or "",
            environment_label_color=d.get("environmentLabelColor"), time_zone=d.get("timeZone") or "UTC",
            date_format=d.get("dateFormat") or "yyyy-MM-dd", support_contact=d.get("supportContact") or "",
            idle_timeout_minutes=int(d.get("idleTimeoutMinutes", 30)), absolute_timeout_minutes=int(d.get("absoluteTimeoutMinutes", 480)),
            banner=BannerSettings.from_dict(d.get("banner")),
        )


# ------------------------------------------------------------------------------------------------ modules

@dataclass
class ModulesSettings:
    enabled: dict[str, bool] = field(default_factory=dict)  # module id -> enabled; modules not listed are enabled

    def to_dict(self) -> dict:
        return {"enabled": dict(self.enabled)}

    @staticmethod
    def from_dict(d: dict | None) -> ModulesSettings:
        return ModulesSettings({k: bool(v) for k, v in ((d or {}).get("enabled") or {}).items()})


# ------------------------------------------------------------------------------------------------ action policies

class ActionKeys:
    RESET_PASSWORD = "resetPassword"
    UNLOCK = "unlock"
    ENABLE_USER = "enableUser"
    DISABLE_USER = "disableUser"
    MOVE_USER = "moveUser"
    ADD_TO_GROUPS = "addToGroups"
    REMOVE_FROM_GROUPS = "removeFromGroups"
    ENABLE_COMPUTER = "enableComputer"
    DISABLE_COMPUTER = "disableComputer"
    MOVE_COMPUTER = "moveComputer"
    ALL = [RESET_PASSWORD, UNLOCK, ENABLE_USER, DISABLE_USER, MOVE_USER, ADD_TO_GROUPS, REMOVE_FROM_GROUPS, ENABLE_COMPUTER, DISABLE_COMPUTER, MOVE_COMPUTER]


@dataclass
class ActionPolicy:
    justification_required: bool = False
    justification_min_length: int = 10
    ticket_required: bool = False
    ticket_pattern: str | None = None
    typed_confirmation_required: bool = False

    def to_dict(self) -> dict:
        return {
            "justificationRequired": self.justification_required, "justificationMinLength": self.justification_min_length,
            "ticketRequired": self.ticket_required, "ticketPattern": self.ticket_pattern,
            "typedConfirmationRequired": self.typed_confirmation_required,
        }

    @staticmethod
    def from_dict(d: dict | None) -> ActionPolicy:
        d = d or {}
        return ActionPolicy(
            bool(d.get("justificationRequired", False)), int(d.get("justificationMinLength", 10)), bool(d.get("ticketRequired", False)),
            d.get("ticketPattern"), bool(d.get("typedConfirmationRequired", False)))

    @staticmethod
    def default_for(key: str) -> ActionPolicy:
        return ActionPolicy(
            justification_required=True, justification_min_length=10, ticket_required=False,
            typed_confirmation_required=key in (ActionKeys.DISABLE_USER, ActionKeys.DISABLE_COMPUTER, ActionKeys.RESET_PASSWORD))


@dataclass
class ActionPoliciesSettings:
    actions: dict[str, ActionPolicy] = field(default_factory=lambda: {k: ActionPolicy.default_for(k) for k in ActionKeys.ALL})
    must_change_password_default: bool = True
    generated_password_length: int = 16

    def to_dict(self) -> dict:
        return {
            "actions": {k: v.to_dict() for k, v in self.actions.items()},
            "mustChangePasswordDefault": self.must_change_password_default, "generatedPasswordLength": self.generated_password_length,
        }

    @staticmethod
    def from_dict(d: dict | None) -> ActionPoliciesSettings:
        d = d or {}
        defaults = ActionPoliciesSettings()
        actions = {k: ActionPolicy.from_dict(v) for k, v in (d.get("actions") or {}).items()} if d.get("actions") is not None else defaults.actions
        return ActionPoliciesSettings(actions, bool(d.get("mustChangePasswordDefault", True)), int(d.get("generatedPasswordLength", 16)))


# ------------------------------------------------------------------------------------------------ branding

COLOR_KEYS = ["primary", "topBarBackground", "navBackground", "navText", "navSelected", "pageBackground", "cardBackground",
              "sectionHeader", "success", "warning", "error"]


@dataclass
class ThemeColors:
    primary: str = "#1f5fbf"
    top_bar_background: str = "#ffffff"
    nav_background: str = "#1b2433"
    nav_text: str = "#e6ebf3"
    nav_selected: str = "#2f4570"
    page_background: str = "#f3f5f9"
    card_background: str = "#ffffff"
    section_header: str = "#1b2433"
    success: str = "#146c2e"
    warning: str = "#8a5a00"
    error: str = "#b3261e"

    def to_dict(self) -> dict:
        return {
            "primary": self.primary, "topBarBackground": self.top_bar_background, "navBackground": self.nav_background,
            "navText": self.nav_text, "navSelected": self.nav_selected, "pageBackground": self.page_background,
            "cardBackground": self.card_background, "sectionHeader": self.section_header, "success": self.success,
            "warning": self.warning, "error": self.error,
        }

    @staticmethod
    def from_dict(d: dict | None, fallback: ThemeColors | None = None) -> ThemeColors:
        base = fallback or ThemeColors()
        d = d or {}
        return ThemeColors(
            d.get("primary", base.primary), d.get("topBarBackground", base.top_bar_background), d.get("navBackground", base.nav_background),
            d.get("navText", base.nav_text), d.get("navSelected", base.nav_selected), d.get("pageBackground", base.page_background),
            d.get("cardBackground", base.card_background), d.get("sectionHeader", base.section_header), d.get("success", base.success),
            d.get("warning", base.warning), d.get("error", base.error))

    @staticmethod
    def default_light() -> ThemeColors:
        return ThemeColors()

    @staticmethod
    def default_dark() -> ThemeColors:
        return ThemeColors("#7aa7f5", "#161c28", "#0f141d", "#d5dbe6", "#26385a", "#0b0f16", "#171e2b", "#e6ebf3", "#5fd08a", "#e5b25d", "#ff8a80")


@dataclass
class BrandingSettings:
    light: ThemeColors = field(default_factory=ThemeColors.default_light)
    dark: ThemeColors = field(default_factory=ThemeColors.default_dark)

    def to_dict(self) -> dict:
        return {"light": self.light.to_dict(), "dark": self.dark.to_dict()}

    @staticmethod
    def from_dict(d: dict | None) -> BrandingSettings:
        d = d or {}
        return BrandingSettings(ThemeColors.from_dict(d.get("light"), ThemeColors.default_light()), ThemeColors.from_dict(d.get("dark"), ThemeColors.default_dark()))


SettingDoc = Any
__all__ = ["BannerSettings", "GeneralSettings", "ModulesSettings", "ActionKeys", "ActionPolicy", "ActionPoliciesSettings", "ThemeColors", "BrandingSettings", "COLOR_KEYS", "P"]
