"""Configuration: JSON files layered like appsettings.json, plus environment variables.

Order (later wins):
  config/settings.json                 shipped defaults (placeholders like <DATA_DIRECTORY>)
  config/settings.<environment>.json   for example settings.development.json
  config/settings.local.json           your own machine only, git-ignored (put secrets here)
  environment variables                SD__Okta__ClientSecret=...  (double underscore separates levels)

The environment name comes from SD_ENVIRONMENT (default: Production).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

PLACEHOLDER = re.compile(r"^<[A-Za-z0-9_]+>$")
ROOT = Path(__file__).resolve().parent.parent


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and bool(PLACEHOLDER.match(value.strip()))


@dataclass
class AppOptions:
    product_name: str = "IT Administration Dashboard"
    environment: str = "Development"
    data_directory: str = ""
    asset_directory: str = ""
    backup_directory: str = ""
    backup_retention_count: int = 7
    daily_backup_enabled: bool = False
    bootstrap_admin_okta_group: str = ""
    dashboard_cache_minutes: int = 5
    export_row_limit: int = 50_000
    audit_retention_days: int = 365
    logo_max_bytes: int = 512 * 1024
    search_rate_limit_per_minute: int = 120
    write_rate_limit_per_minute: int = 60


@dataclass
class OktaOptions:
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    groups_claim: str = "groups"
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email", "groups"])
    development_sign_in: bool = False


@dataclass
class ActiveDirectoryOptions:
    provider: str = "Fake"  # "Ldap" or "Fake"
    domain: str = ""
    server: str = ""
    port: int = 636
    use_ldaps: bool = True
    base_dn: str = ""
    verify_certificate: bool = True  # must stay true in Production
    # LOCAL TESTING ONLY: bind with this account instead of the machine identity. The app refuses to start outside Development if set.
    bind_username: str = ""
    bind_password: str = ""
    # Fake provider only: make every call fail as if the domain controller were unreachable.
    simulate_server_unavailable: bool = False


def _pascal_to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _merge(base: dict, extra: dict) -> dict:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def _fill(obj: Any, data: dict) -> None:
    """Copy a JSON section (PascalCase keys) onto a dataclass, coercing types and blanking placeholders."""
    by_name = {f.name: f for f in fields(obj)}
    for key, raw in data.items():
        name = _pascal_to_snake(key)
        f = by_name.get(name)
        if f is None:
            continue
        current = getattr(obj, name)
        if isinstance(raw, str) and is_placeholder(raw):
            raw = ""
        if isinstance(current, bool):
            raw = raw if isinstance(raw, bool) else str(raw).strip().lower() in ("1", "true", "yes", "on")
        elif isinstance(current, int):
            raw = int(raw)
        elif isinstance(current, list):
            raw = list(raw) if isinstance(raw, (list, tuple)) else [s for s in str(raw).split(",") if s.strip()]
        elif isinstance(current, str):
            raw = "" if raw is None else str(raw)
        setattr(obj, name, raw)


@dataclass
class Settings:
    environment: str
    app: AppOptions
    okta: OktaOptions
    ad: ActiveDirectoryOptions
    log_directory: str
    raw: dict
    root: Path

    @property
    def is_development(self) -> bool:
        return self.environment.lower() == "development"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


def load_settings(environment: str | None = None, overrides: dict | None = None, root: Path | None = None) -> Settings:
    root = root or ROOT
    env = environment or os.environ.get("SD_ENVIRONMENT", "Production")
    merged: dict = {}
    for name in ("settings.json", f"settings.{env.lower()}.json", "settings.local.json"):
        p = root / "config" / name
        if p.exists():
            _merge(merged, json.loads(p.read_text(encoding="utf-8")))
    for key, value in os.environ.items():
        if key.startswith("SD__"):
            parts = key[4:].split("__")
            node = merged
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = value
    if overrides:
        _merge(merged, overrides)

    app, okta, ad = AppOptions(), OktaOptions(), ActiveDirectoryOptions()
    _fill(app, merged.get("App", {}))
    _fill(okta, merged.get("Okta", {}))
    _fill(ad, merged.get("ActiveDirectory", {}))
    log_dir = (merged.get("Serilog", {}) or merged.get("Logging", {})).get("LogDirectory", "")
    if is_placeholder(log_dir):
        log_dir = ""
    return Settings(env, app, okta, ad, log_dir or "", merged, root)


def validate_startup(s: Settings) -> list[str]:
    """Everything that must be fixed before the application may start (unsafe or incomplete configuration)."""
    errors: list[str] = []
    okta, ad, app = s.okta, s.ad, s.app

    if okta.development_sign_in and not s.is_development:
        errors.append("Okta:DevelopmentSignIn is enabled but the environment is not Development. Development sign-in is for local testing only.")
    if not s.is_development and (ad.bind_username or ad.bind_password):
        errors.append("ActiveDirectory:BindUsername/BindPassword are for local testing only. Outside Development the application binds as its own identity and no AD password may be configured.")
    if ad.provider not in ("Ldap", "Fake"):
        errors.append(f"ActiveDirectory:Provider must be 'Ldap' or 'Fake' (was '{ad.provider}').")

    if s.is_production:
        if ad.provider == "Fake":
            errors.append("ActiveDirectory:Provider is 'Fake' in Production. Use 'Ldap'.")
        if not ad.verify_certificate:
            errors.append("ActiveDirectory:VerifyCertificate is false in Production. LDAP certificate checks must stay on.")
        if ad.provider == "Ldap" and not ad.use_ldaps:
            errors.append("ActiveDirectory:UseLdaps is false in Production. LDAP must use LDAPS.")
        pairs: list[tuple[str, str]] = []
        if ad.provider == "Ldap":
            pairs += [("ActiveDirectory:Domain", ad.domain), ("ActiveDirectory:Server", ad.server), ("ActiveDirectory:BaseDn", ad.base_dn)]
        if not okta.development_sign_in:
            pairs += [("Okta:Issuer", okta.issuer), ("Okta:ClientId", okta.client_id), ("Okta:ClientSecret", okta.client_secret)]
        pairs += [("App:DataDirectory", app.data_directory), ("App:AssetDirectory", app.asset_directory), ("Serilog:LogDirectory", s.log_directory)]
        for name, value in pairs:
            if not value.strip() or is_placeholder(value):
                errors.append(f"{name} is not set (still empty or a <PLACEHOLDER>).")
    return errors
