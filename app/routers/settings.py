"""Public branding, the app-shell bootstrap, and the General / Modules / Action-Policies settings (validated and audited)."""
from __future__ import annotations

import re
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import regex
from fastapi import APIRouter, Body, Depends

from .. import permissions as P
from ..audit import AuditEntry
from ..db import LogoAsset
from ..errors import ApiException
from ..http_helpers import ok, problem
from ..module_catalog import COMING_SOON
from ..settings_models import ActionKeys, ActionPoliciesSettings, ActionPolicy, BannerSettings, GeneralSettings, ThemeColors
from ..settings_service import dumps
from ..util import iso
from ..web import Ctx, get_ctx, guard
from sqlalchemy import select

router = APIRouter(prefix="/api/settings")

DATE_FORMATS = ["yyyy-MM-dd", "dd/MM/yyyy", "MM/dd/yyyy"]
BANNER_TYPES = ["Information", "Warning", "Maintenance"]
BANNER_MAX_LENGTH = 300
_HEX6 = re.compile(r"\A#[0-9a-fA-F]{6}\Z")


def invalid(message: str) -> ApiException:
    return ApiException(400, "Invalid setting", message, "validation")


def find_zone(tz_id: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz_id)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return ZoneInfo("UTC")


def _parse_local(s: str | None) -> datetime | None:
    """Wall-clock time as 'yyyy-MM-ddTHH:mm' (or with seconds); anything else is not a valid banner time."""
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return None


def active_banner(g: GeneralSettings, now_utc: datetime | None = None) -> dict | None:
    """The banner to show right now, or None when disabled or outside its start and end times."""
    b = g.banner
    if not b.enabled or not b.text.strip():
        return None
    from ..util import utcnow

    now = (now_utc or utcnow()).astimezone(find_zone(g.time_zone)).replace(tzinfo=None)
    start, end = _parse_local(b.start_local), _parse_local(b.end_local)
    if start is not None and now < start:
        return None
    if end is not None and now > end:
        return None
    return {"type": b.type, "text": b.text, "dismissible": b.type == "Information"}


@router.get("/branding")
def branding(ctx: Ctx = Depends(get_ctx), _=Depends(guard(anonymous=True))):
    """Branding for the login page and the shell. Contains no secrets, so it is public."""
    general, b = ctx.settings.general(), ctx.settings.branding()
    logos = list(ctx.db.scalars(select(LogoAsset)))
    kinds = {x.kind for x in logos}
    return ok({
        "productName": general.product_name, "light": b.light.to_dict(), "dark": b.dark.to_dict(),
        "hasLogoLight": "logoLight" in kinds, "hasLogoDark": "logoDark" in kinds, "hasFavicon": "favicon" in kinds,
        # Changes whenever a logo changes, so browsers fetch the new image.
        "assetVersion": "0" if not logos else str(max(int(x.updated_utc.timestamp() * 1e6) for x in logos)),
    })


@router.get("/shell")
def shell(ctx: Ctx = Depends(get_ctx), _=Depends(guard(authenticated_only=True))):
    """What the app shell needs after sign-in: labels, time zone, active banner and module states."""
    g = ctx.settings.general()
    return ok({
        "productName": g.product_name, "environmentLabel": g.environment_label, "environmentLabelColor": g.environment_label_color or "",
        "timeZone": g.time_zone, "dateFormat": g.date_format, "supportContact": g.support_contact,
        "idleTimeoutMinutes": g.idle_timeout_minutes, "banner": active_banner(g), "actionPolicies": ctx.settings.action_policies().to_dict(),
        "modules": ctx.modules.list(),
    })


# ------------------------------------------------------------------------------------------------ General (+ banner)

@router.get("/general")
def get_general(ctx: Ctx = Depends(get_ctx), _=Depends(guard(*P.SETTINGS_ACCESS))):
    return ok(ctx.settings.general().to_dict())


def _validate_general(v: GeneralSettings) -> GeneralSettings:
    name = (v.product_name or "").strip()
    if not 1 <= len(name) <= 100:
        raise invalid("The product name must be 1 to 100 characters.")
    env = (v.environment_label or "").strip()
    if len(env) > 30:
        raise invalid("The environment label can be up to 30 characters.")
    color = (v.environment_label_color or "").strip()
    if color and not _HEX6.match(color):
        raise invalid("The environment label colour must look like #1f5fbf.")
    tz = (v.time_zone or "").strip()
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise invalid(f"'{tz}' is not a known time zone. Use an IANA name such as Europe/London or UTC.") from None
    if v.date_format not in DATE_FORMATS:
        raise invalid("Choose one of the listed date formats.")
    support = (v.support_contact or "").strip()
    if len(support) > 200:
        raise invalid("The support contact can be up to 200 characters.")
    if not 5 <= v.idle_timeout_minutes <= 1440:
        raise invalid("The idle timeout must be between 5 and 1440 minutes.")
    if not 15 <= v.absolute_timeout_minutes <= 10080:
        raise invalid("The absolute session lifetime must be between 15 minutes and 7 days.")
    if v.absolute_timeout_minutes < v.idle_timeout_minutes:
        raise invalid("The absolute session lifetime cannot be shorter than the idle timeout.")

    b = v.banner or BannerSettings()
    text = (b.text or "").strip()
    if b.type not in BANNER_TYPES:
        raise invalid("The banner type must be Information, Warning or Maintenance.")
    if len(text) > BANNER_MAX_LENGTH:
        raise invalid(f"The banner text can be up to {BANNER_MAX_LENGTH} characters.")
    if "<" in text or ">" in text:
        raise invalid("The banner text is plain text only. Remove any HTML.")
    if b.enabled and not text:
        raise invalid("Enter the banner text, or turn the banner off.")

    def parse(s: str | None, what: str) -> datetime | None:
        if not s or not s.strip():
            return None
        d = _parse_local(s)
        if d is None:
            raise invalid(f"The banner {what} time is not a valid date and time.")
        return d

    start, end = parse(b.start_local, "start"), parse(b.end_local, "end")
    if start is not None and end is not None and end <= start:
        raise invalid("The banner end must be after its start.")
    fmt = "%Y-%m-%dT%H:%M"
    return GeneralSettings(
        product_name=name, environment_label=env, environment_label_color=color.lower(), time_zone=tz, date_format=v.date_format,
        support_contact=support, idle_timeout_minutes=v.idle_timeout_minutes, absolute_timeout_minutes=v.absolute_timeout_minutes,
        banner=BannerSettings(b.enabled, b.type, text, start.strftime(fmt) if start else None, end.strftime(fmt) if end else None))


def _int(d: dict, key: str, default: int = 0) -> int:
    v = d.get(key, default)
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        raise invalid(f"'{key}' must be a number.")
    try:
        return int(v)
    except ValueError:
        raise invalid(f"'{key}' must be a number.") from None


@router.put("/general")
def put_general(body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.SETTINGS_MANAGE))):
    current = ctx.settings.general()
    idle, absolute = _int(body, "idleTimeoutMinutes", 30), _int(body, "absoluteTimeoutMinutes", 480)
    value = GeneralSettings.from_dict({**body, "idleTimeoutMinutes": idle, "absoluteTimeoutMinutes": absolute})
    if value.environment_label_color is None:  # a client that does not send the colour keeps what is set
        value.environment_label_color = current.environment_label_color or ""
    nxt = _validate_general(value)
    ctx.settings.save_general(nxt, user.display_name)

    # The banner is audited on its own so creating, changing or removing it is easy to find.
    before, after = dumps(current.to_dict_without_banner()), dumps(nxt.to_dict_without_banner())
    if before != after:
        ctx.audit.write(AuditEntry(action="settings.general.update", module="core", target="General settings", previous_value=before, new_value=after))
    b_before, b_after = dumps(current.banner.to_dict()), dumps(nxt.banner.to_dict())
    if b_before != b_after:
        had = current.banner.enabled and len(current.banner.text) > 0
        has = nxt.banner.enabled and len(nxt.banner.text) > 0
        action = "settings.banner.create" if not had and has else "settings.banner.remove" if had and not has else "settings.banner.update"
        ctx.audit.write(AuditEntry(action=action, module="core", target="Application banner", previous_value=b_before, new_value=b_after))
    return ok(nxt.to_dict())


# ------------------------------------------------------------------------------------------------ Modules

@router.get("/modules")
def get_modules(ctx: Ctx = Depends(get_ctx), _=Depends(guard(*P.SETTINGS_ACCESS))):
    return ok(ctx.modules.list())


@router.put("/modules/{module_id}")
def put_module(module_id: str, body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.SETTINGS_MANAGE))):
    if not any(m.id == module_id for m in ctx.state.modules):
        detail = "This module is Coming Soon and cannot be enabled yet." if any(m.id == module_id for m in COMING_SOON) else "Unknown module."
        return problem(400, "Cannot change this module", detail)
    current = ctx.settings.modules()
    was = current.enabled.get(module_id, True)
    enabled = bool(body.get("enabled", False))
    current.enabled[module_id] = enabled
    ctx.settings.save_modules(current, user.display_name)
    if was != enabled:
        ctx.audit.write(AuditEntry(action="settings.modules.update", module="core", target="Module: " + module_id,
                                   previous_value="Enabled" if was else "Disabled", new_value="Enabled" if enabled else "Disabled"))
    return ok(ctx.modules.list())


# ------------------------------------------------------------------------------------------------ Action policies

@router.get("/action-policies")
def get_policies(ctx: Ctx = Depends(get_ctx), _=Depends(guard(*P.SETTINGS_ACCESS))):
    return ok(ctx.settings.action_policies().to_dict())


@router.put("/action-policies")
def put_policies(body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.SETTINGS_MANAGE))):
    actions_in = body.get("actions")
    nxt = ActionPoliciesSettings(actions={})
    for key in ActionKeys.ALL:
        if not isinstance(actions_in, dict) or key not in actions_in:
            raise invalid(f"The policy for '{key}' is missing.")
        p = ActionPolicy.from_dict(actions_in[key])
        pattern = (p.ticket_pattern or "").strip() or None
        if pattern is not None:
            if len(pattern) > 200:
                raise invalid("A ticket pattern can be up to 200 characters.")
            try:
                regex.match(pattern, "INC-0001", timeout=0.25)
            except (regex.error, TimeoutError):
                raise invalid(f"The ticket pattern for '{key}' is not a valid regular expression.") from None
        if not 0 <= p.justification_min_length <= 500:
            raise invalid("The minimum justification length must be between 0 and 500.")
        if p.justification_required and p.justification_min_length < 1:
            raise invalid("A required justification needs a minimum length of at least 1.")
        nxt.actions[key] = ActionPolicy(p.justification_required, p.justification_min_length, p.ticket_required, pattern, p.typed_confirmation_required)
    length = _int(body, "generatedPasswordLength", 16)
    if not 8 <= length <= 128:
        raise invalid("The generated password length must be between 8 and 128.")
    nxt.generated_password_length = length
    nxt.must_change_password_default = bool(body.get("mustChangePasswordDefault", True))
    before, after = ctx.settings.save_action_policies(nxt, user.display_name)
    if before != after:
        ctx.audit.write(AuditEntry(action="settings.actionPolicies.update", module="core", target="Action policies", previous_value=before, new_value=after))
    return ok(nxt.to_dict())


__all__ = ["router", "active_banner", "find_zone", "iso", "ThemeColors"]
