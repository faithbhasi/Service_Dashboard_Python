"""Per-request facts (who, from where, which correlation id) that the audit log and the logs need anywhere in the call stack."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass
class RequestInfo:
    correlation_id: str = ""
    ip_address: str | None = None
    user_agent: str | None = None
    # Set once the signed-in user is known (an authenticated request, or a sign-in).
    user_id: str | None = None
    user_name: str | None = None


_current: ContextVar[RequestInfo | None] = ContextVar("request_info", default=None)


def set_request_info(info: RequestInfo | None) -> None:
    _current.set(info)


def request_info() -> RequestInfo | None:
    return _current.get()


def correlation_id() -> str:
    info = _current.get()
    return info.correlation_id if info else ""
