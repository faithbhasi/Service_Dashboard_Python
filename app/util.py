"""Small helpers shared by the whole application: GUIDs, UTC time, JSON naming."""
from __future__ import annotations

import dataclasses
import enum
import re
import uuid
from datetime import UTC, datetime
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """Treat a naive datetime as UTC and convert an aware one to UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def iso(value: datetime | None) -> str | None:
    """ISO 8601 in UTC with a trailing Z, the way the front end expects it."""
    if value is None:
        return None
    return as_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def new_id() -> str:
    return str(uuid.uuid4())


def parse_guid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def to_camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def jsonable(obj: Any) -> Any:
    """Turn dataclasses, enums, GUIDs and datetimes into plain JSON data with camelCase keys."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, enum.Enum):
        return obj.name
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return iso(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {to_camel(f.name.rstrip('_')): jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, dict):
        return {(k if isinstance(k, str) else str(k)): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in obj]
    raise TypeError(f"Cannot serialise {type(obj)!r}")


def like_pattern(text: str) -> str:
    """'contains' pattern with LIKE wildcards in the user's text escaped (use with escape='\\')."""
    t = text.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{t}%"


def ordinal_key(value: str | None) -> str:
    """Sort key matching .NET StringComparer.OrdinalIgnoreCase."""
    return (value or "").upper()
