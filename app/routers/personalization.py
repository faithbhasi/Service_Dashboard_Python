"""Logo, favicon, product name and colours. Applies to everyone. Logos are files under the asset directory, metadata is in SQLite."""
from __future__ import annotations

import json
import re

from fastapi import APIRouter, Body, Depends, File, UploadFile
from sqlalchemy import select
from starlette.responses import FileResponse

from .. import permissions as P
from ..audit import AuditEntry
from ..db import LogoAsset
from ..errors import ApiException
from ..http_helpers import no_content, ok, problem
from ..settings_models import BrandingSettings, ThemeColors
from ..settings_service import dumps
from ..util import iso, utcnow
from ..web import Ctx, get_ctx, guard

router = APIRouter(prefix="/api/settings/personalization")

# PNG, JPEG and WebP only. SVG is refused because it can contain scripts.
ALLOWED_TYPES = ["image/png", "image/jpeg", "image/webp"]
KINDS = {"light": "logoLight", "dark": "logoDark", "favicon": "favicon"}
_HEX = re.compile(r"\A#[0-9a-fA-F]{6}\Z")


def invalid(m: str) -> ApiException:
    return ApiException(400, "Invalid setting", m, "validation")


def sniff(b: bytes) -> tuple[str, str] | None:
    """The image type from its bytes, never from the uploaded name or the browser's content type."""
    if len(b) >= 8 and b[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png", ".png"
    if len(b) >= 3 and b[0] == 0xFF and b[1] == 0xD8 and b[2] == 0xFF:
        return "image/jpeg", ".jpg"
    if len(b) >= 12 and b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "image/webp", ".webp"
    return None


def _asset_dto(a: LogoAsset) -> dict:
    return {"fileName": a.file_name, "contentType": a.content_type, "sizeBytes": a.size_bytes, "updatedUtc": iso(a.updated_utc)}


@router.get("")
def get(ctx: Ctx = Depends(get_ctx), _=Depends(guard(*P.SETTINGS_ACCESS))):
    general, b = ctx.settings.general(), ctx.settings.branding()
    logos = {x.kind: _asset_dto(x) for x in ctx.db.scalars(select(LogoAsset))}
    return ok({
        "productName": general.product_name, "light": b.light.to_dict(), "dark": b.dark.to_dict(),
        "defaults": {"light": ThemeColors.default_light().to_dict(), "dark": ThemeColors.default_dark().to_dict()},
        "logos": logos, "maxLogoBytes": ctx.config.app.logo_max_bytes, "allowedTypes": ALLOWED_TYPES,
    })


def _validate_colors(c: dict | None, theme: str) -> ThemeColors:
    if not isinstance(c, dict):
        raise invalid(f"The {theme} colours are missing.")
    labels = [("primary", "primary"), ("topBarBackground", "top bar background"), ("navBackground", "navigation background"),
              ("navText", "navigation text"), ("navSelected", "navigation selected item"), ("pageBackground", "page background"),
              ("cardBackground", "card background"), ("sectionHeader", "section header"), ("success", "success"), ("warning", "warning"),
              ("error", "error")]
    for key, label in labels:
        v = c.get(key)
        if not isinstance(v, str) or not _HEX.match(v):
            raise invalid(f"The {theme} {label} colour must be a hex value such as #1f5fbf.")
    return ThemeColors.from_dict(c)


@router.put("")
def put(body: dict = Body(...), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.SETTINGS_PERSONALIZATION_MANAGE))):
    name = str(body.get("productName") or "").strip()
    if not 1 <= len(name) <= 100:
        raise invalid("The product name must be 1 to 100 characters.")
    light, dark = _validate_colors(body.get("light"), "light"), _validate_colors(body.get("dark"), "dark")

    general = ctx.settings.general()
    old_branding = ctx.settings.branding()
    before, after = ctx.settings.save_branding(BrandingSettings(light, dark), user.display_name)
    old_name = general.product_name
    if old_name != name:
        general.product_name = name
        ctx.settings.save_general(general, user.display_name)
    if before != after or old_name != name:
        ctx.audit.write(AuditEntry(
            action="settings.personalization.update", module="core", target="Personalization",
            previous_value=dumps({"productName": old_name, "light": old_branding.light.to_dict(), "dark": old_branding.dark.to_dict()}),
            new_value=dumps({"productName": name, "light": light.to_dict(), "dark": dark.to_dict()})))
    return ok({"productName": name, "light": light.to_dict(), "dark": dark.to_dict()})


@router.post("/reset-colors")
def reset_colors(ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.SETTINGS_PERSONALIZATION_MANAGE))):
    """Puts the colours (both themes) back to the built-in defaults. The product name and logos are untouched."""
    fresh = BrandingSettings()
    before, after = ctx.settings.save_branding(fresh, user.display_name)
    if before != after:
        ctx.audit.write(AuditEntry(action="settings.personalization.reset", module="core", target="Colours", previous_value=before, new_value=after))
    return ok(fresh.to_dict())


# ------------------------------------------------------------------------------------------------ logo files

@router.get("/logo/{kind}")
def get_logo(kind: str, ctx: Ctx = Depends(get_ctx), _=Depends(guard(anonymous=True))):
    """The image itself. Public (the login page needs it) and served with the type detected from its bytes."""
    key = KINDS.get(kind)
    if key is None:
        return problem(404, "Not Found")
    asset = ctx.db.get(LogoAsset, key)
    if asset is None:
        return problem(404, "Not Found")
    path = ctx.state.paths.logo_directory / asset.file_name
    if not path.is_file():
        return problem(404, "Not Found")
    return FileResponse(path, media_type=asset.content_type, headers={"Cache-Control": "public, max-age=300"})


@router.post("/logo/{kind}")
async def upload(kind: str, file: UploadFile = File(None), ctx: Ctx = Depends(get_ctx), user=Depends(guard(P.SETTINGS_PERSONALIZATION_MANAGE))):
    key = KINDS.get(kind)
    if key is None:
        return problem(404, "Not Found")
    limit = ctx.config.app.logo_max_bytes
    if file is None:
        raise invalid("Choose an image file.")
    data = await file.read(limit + 1)
    if not data:
        raise invalid("Choose an image file.")
    if len(data) > limit:
        raise invalid(f"The image is larger than the limit of {limit // 1024} KB.")
    # Trust the bytes, not the file name or the browser's content type.
    kind_ext = sniff(data)
    if kind_ext is None:
        raise invalid("Only PNG, JPEG and WebP images are accepted. SVG is not allowed because it can contain scripts.")
    ctype, ext = kind_ext

    # Fixed file names per kind: nothing from the upload ever reaches a path.
    folder = ctx.state.paths.logo_directory
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob(key + ".*"):
        old.unlink(missing_ok=True)
    file_name = key + ext
    (folder / file_name).write_bytes(data)

    asset = ctx.db.get(LogoAsset, key)
    had = asset is not None
    if asset is None:
        asset = LogoAsset(kind=key)
        ctx.db.add(asset)
    asset.file_name, asset.content_type, asset.size_bytes, asset.updated_utc = file_name, ctype, len(data), utcnow()
    ctx.db.commit()
    ctx.audit.write(AuditEntry(action="settings.personalization.logo", module="core", target="Logo: " + kind,
                               previous_value="Custom image" if had else "Default", new_value=f"{ctype}, {len(data)} bytes"))
    return ok(_asset_dto(asset))


@router.delete("/logo/{kind}")
def reset_logo(kind: str, ctx: Ctx = Depends(get_ctx), _=Depends(guard(P.SETTINGS_PERSONALIZATION_MANAGE))):
    key = KINDS.get(kind)
    if key is None:
        return problem(404, "Not Found")
    asset = ctx.db.get(LogoAsset, key)
    if asset is None:
        return no_content()
    for f in ctx.state.paths.logo_directory.glob(key + ".*"):
        f.unlink(missing_ok=True)
    ctx.db.delete(asset)
    ctx.db.commit()
    ctx.audit.write(AuditEntry(action="settings.personalization.logo", module="core", target="Logo: " + kind, previous_value="Custom image", new_value="Default"))
    return no_content()


__all__ = ["router", "sniff", "json"]
