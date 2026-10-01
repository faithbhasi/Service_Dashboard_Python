from __future__ import annotations

import json
from typing import Any

from starlette.responses import JSONResponse, Response

from .request_context import correlation_id
from .util import jsonable


class ApiJSON(JSONResponse):
    """JSON with camelCase keys, GUIDs and UTC timestamps rendered the way the front end expects."""

    def render(self, content: Any) -> bytes:
        return json.dumps(jsonable(content), ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def ok(content: Any = None, status: int = 200, headers: dict | None = None) -> Response:
    return ApiJSON(content if content is not None else {}, status_code=status, headers=headers)


def no_content() -> Response:
    return Response(status_code=204)


def problem(status: int, title: str, detail: str | None = None, code: str | None = None, **extra: Any) -> Response:
    body: dict[str, Any] = {"type": f"https://httpstatuses.io/{status}", "title": title, "status": status}
    if detail:
        body["detail"] = detail
    if code:
        body["code"] = code
    body["correlationId"] = correlation_id()
    body.update(extra)
    return ApiJSON(body, status_code=status, media_type="application/problem+json")
