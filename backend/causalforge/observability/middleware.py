"""HTTP request correlation middleware."""

import re
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from causalforge.observability.logging import request_id_context

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a bounded request ID to logs and the response without trusting user input."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID")
        if not request_id or not _SAFE_REQUEST_ID.fullmatch(request_id):
            request_id = str(uuid4())
        token = request_id_context.set(request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_context.reset(token)
