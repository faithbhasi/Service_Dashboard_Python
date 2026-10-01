"""Runtime settings stored as one JSON document per key in SQLite, cached in memory until saved."""
from __future__ import annotations

import json
import threading
from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy.orm import Session

from .config import AppOptions
from .db import SettingEntry
from .settings_models import ActionPoliciesSettings, BrandingSettings, GeneralSettings, ModulesSettings
from .util import utcnow

T = TypeVar("T")


class SettingKeys:
    GENERAL = "general"
    MODULES = "modules"
    ACTION_POLICIES = "actionPolicies"
    BRANDING = "branding"
    ACTIVE_DIRECTORY = "ad"


class SettingsCache:
    """Shared by every request of one application instance."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> str | None:
        with self._lock:
            return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._data[key] = value

    def remove(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


def dumps(d: Any) -> str:
    return json.dumps(d, separators=(",", ":"), ensure_ascii=False)


class SettingsService:
    def __init__(self, db: Session, cache: SettingsCache, app: AppOptions):
        self.db = db
        self.cache = cache
        self.app = app

    # ---- generic documents: (from_dict, default factory) pairs keep the types honest

    def get_doc(self, key: str, from_dict: Callable[[dict | None], T], defaults: Callable[[], T]) -> T:
        cached = self.cache.get(key)
        if cached is None:
            entry = self.db.get(SettingEntry, key)
            cached = entry.json if entry is not None else dumps(defaults().to_dict())  # type: ignore[attr-defined]
            self.cache.set(key, cached)
        try:
            return from_dict(json.loads(cached))
        except (ValueError, TypeError):
            return defaults()

    def save_doc(self, key: str, value: Any, updated_by: str | None, from_dict: Callable[[dict | None], Any], defaults: Callable[[], Any]) -> tuple[str, str]:
        """Saves and returns (before, after) JSON for the audit record."""
        before = dumps(self.get_doc(key, from_dict, defaults).to_dict())
        after = dumps(value.to_dict())
        entry = self.db.get(SettingEntry, key)
        if entry is None:
            entry = SettingEntry(key=key)
            self.db.add(entry)
        entry.json = after
        entry.updated_utc = utcnow()
        entry.updated_by = updated_by
        self.db.commit()
        self.cache.remove(key)
        return before, after

    # ---- typed accessors

    def default_general(self) -> GeneralSettings:
        return GeneralSettings(product_name=self.app.product_name, environment_label=self.app.environment, environment_label_color="")

    def general(self) -> GeneralSettings:
        g = self.get_doc(SettingKeys.GENERAL, GeneralSettings.from_dict, self.default_general)
        if not g.product_name:
            g.product_name = self.app.product_name
        return g

    def save_general(self, value: GeneralSettings, by: str | None) -> tuple[str, str]:
        return self.save_doc(SettingKeys.GENERAL, value, by, GeneralSettings.from_dict, self.default_general)

    def modules(self) -> ModulesSettings:
        return self.get_doc(SettingKeys.MODULES, ModulesSettings.from_dict, ModulesSettings)

    def save_modules(self, value: ModulesSettings, by: str | None) -> tuple[str, str]:
        return self.save_doc(SettingKeys.MODULES, value, by, ModulesSettings.from_dict, ModulesSettings)

    def action_policies(self) -> ActionPoliciesSettings:
        return self.get_doc(SettingKeys.ACTION_POLICIES, ActionPoliciesSettings.from_dict, ActionPoliciesSettings)

    def save_action_policies(self, value: ActionPoliciesSettings, by: str | None) -> tuple[str, str]:
        return self.save_doc(SettingKeys.ACTION_POLICIES, value, by, ActionPoliciesSettings.from_dict, ActionPoliciesSettings)

    def branding(self) -> BrandingSettings:
        return self.get_doc(SettingKeys.BRANDING, BrandingSettings.from_dict, BrandingSettings)

    def save_branding(self, value: BrandingSettings, by: str | None) -> tuple[str, str]:
        return self.save_doc(SettingKeys.BRANDING, value, by, BrandingSettings.from_dict, BrandingSettings)
