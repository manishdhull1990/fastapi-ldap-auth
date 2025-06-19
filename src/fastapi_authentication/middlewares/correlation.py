import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from contextvars import ContextVar

correlation_id_ctx = ContextVar("correlation_id", default=None)

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Check if incoming request has a correlation ID header
        cid = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        print(f"[Middleware] setting CID = {cid}")
        correlation_id_ctx.set(cid)
        
        response: Response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid  # Return it in response
        return response

def get_correlation_id():
    return correlation_id_ctx.get()