import inspect
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging
from fastapi.responses import JSONResponse

from stufio.api import deps
from stufio.db.clickhouse import ClickhouseDatabase
from app.config import settings
from stufio.api.deps import get_db
from ..crud.crud_rate_limit import crud_rate_limit

logger = logging.getLogger(__name__)

class RateLimitingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        # Extract basic request info
        path = request.url.path
        client_ip = self._get_client_ip(request)

        # Skip rate limiting for certain paths
        if path in [
            "/metrics",
            "/health",
            settings.API_V1_STR + "/docs",
            settings.API_V1_STR + "/openapi.json",
        ]:
            return await call_next(request)

        try:
            db = None
            db_generator = get_db()

            # Check if get_db returns an async generator or regular generator
            if inspect.isasyncgen(db_generator):
                # It's an async generator - use anext
                db = await anext(db_generator)
            else:
                # It's a regular generator - use next
                db = next(db_generator)
            clickhouse_db = await ClickhouseDatabase()

            # Get current user if authenticated
            user_id = None
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.replace("Bearer ", "")
                try:
                    token_data = deps.get_token_payload(token)
                    user_id = token_data.sub
                except Exception as e:
                    logger.debug(f"Error extracting user from token: {e}")

            # Apply rate limits
            # 1. IP-based rate limiting (prevents DDoS)
            if not await crud_rate_limit.check_and_update_ip_limit(
                db=db, 
                clickhouse_db=clickhouse_db,
                ip=client_ip,
                max_requests=settings.RATE_LIMIT_IP_MAX_REQUESTS,
                window_seconds=settings.RATE_LIMIT_IP_WINDOW_SECONDS
            ):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests from this IP address"}
                )

            # 2. User-based rate limiting (if authenticated)
            if user_id and not await crud_rate_limit.check_and_update_user_limit(
                db=db,
                clickhouse_db=clickhouse_db,
                user_id=str(user_id),
                path=path,
                max_requests=settings.RATE_LIMIT_USER_MAX_REQUESTS,
                window_seconds=settings.RATE_LIMIT_USER_WINDOW_SECONDS,
            ):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests - please slow down"}
                )

            # 3. Endpoint-specific rate limiting (from MongoDB)
            endpoint_config = await crud_rate_limit.get_rate_limit_config(
                db, endpoint=path
            )

            # Check if user has a role that bypasses rate limit
            # if endpoint_config and []:
            #     bypass_roles = endpoint_config.get("bypass_roles", [])
            #     if any(role in bypass_roles for role in user_roles):
            #         # User has a bypass role, skip endpoint rate limiting
            #         return await call_next(request)

            # Apply endpoint-specific rate limiting if configured
            if endpoint_config:
                max_requests = endpoint_config.get("max_requests", 100)
                window_seconds = endpoint_config.get("window_seconds", 60)

                if not await crud_rate_limit.check_and_update_endpoint_limit(
                    db, clickhouse_db, path, client_ip, max_requests, window_seconds
                ):
                    return JSONResponse(
                        status_code=429,
                        content={"detail": f"Rate limit exceeded for {path}"},
                    )
        except Exception as e:
            # Log the error but allow the request to continue to avoid blocking legitimate requests
            logger.error(f"Error in rate limiting checks: {str(e)}")

        # Process the request if rate limits are not exceeded or there was an error
        return await call_next(request)

    # The same helper method as in the ActivityTrackingMiddleware
    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP from request headers"""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Get the first IP if multiple are provided
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
