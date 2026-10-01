from __future__ import annotations

from dataclasses import dataclass

from .settings_service import SettingsService


@dataclass(frozen=True)
class ModuleDescriptor:
    """A module registers one of these. Module ids are lowercase and never change."""

    id: str
    name: str
    description: str


# Planned modules, shown in Settings and the navigation as "Coming Soon".
COMING_SOON = [
    ModuleDescriptor("okta", "Okta", "Okta user and group administration."),
    ModuleDescriptor("m365", "Microsoft 365", "Microsoft 365 licences and mailboxes."),
    ModuleDescriptor("mimecast", "Mimecast", "Mimecast email security."),
    ModuleDescriptor("citrix", "Citrix", "Citrix sessions and applications."),
]


class ModuleCatalog:
    def __init__(self, modules: list[ModuleDescriptor], settings: SettingsService):
        self.modules = modules
        self.settings = settings

    def is_enabled(self, module_id: str) -> bool:
        if not any(m.id == module_id for m in self.modules):
            return False
        return self.settings.modules().enabled.get(module_id, True)

    def list(self) -> list[dict]:
        s = self.settings.modules()
        out = []
        for m in self.modules:
            on = s.enabled.get(m.id, True)
            out.append({"id": m.id, "name": m.name, "description": m.description, "status": "Active" if on else "Disabled", "enabled": on})
        out += [{"id": m.id, "name": m.name, "description": m.description, "status": "Coming Soon", "enabled": False} for m in COMING_SOON]
        return out
