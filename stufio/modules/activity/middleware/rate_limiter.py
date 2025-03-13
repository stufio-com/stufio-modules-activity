import inspect
import asyncio
from ipaddress import ip_address
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging
from fastapi.responses import JSONResponse

from stufio.api import deps
from stufio.db.clickhouse import ClickhouseDatabase
from stufio.core.config import get_settings
from stufio.api.deps import get_db
from ..crud import crud_rate_limit, crud_activity
from ..services.rate_limit import rate_limit_service


settings = get_settings()
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

            # Check if user is already rate limited in MongoDB
            if user_id:
                is_limited, reason = await crud_rate_limit.is_user_rate_limited(db=db, user_id=user_id)
                if is_limited:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": reason or "Rate limited"}
                    )

            # IP-based rate limiting
            ip_allowed = await rate_limit_service.check_limit(
                key=f"ip:{client_ip}",
                max_requests=settings.activity_RATE_LIMIT_IP_MAX_REQUESTS,
                window_seconds=settings.activity_RATE_LIMIT_IP_WINDOW_SECONDS,
                clickhouse_db=clickhouse_db,
                record_type="ip",
                record_data={"ip": client_ip},
            )

            if not ip_allowed:
                # Store persistent rate limit in MongoDB
                asyncio.create_task(crud_rate_limit.set_user_rate_limited(
                    db=db,
                    user_id=f"ip:{client_ip}",
                    reason="IP-based rate limit exceeded",
                    duration_minutes=15
                ))

                return JSONResponse(
                    status_code=429, 
                    content={"detail": "Too many requests from this IP address"}
                )

            # IP blacklist check
            is_blacklisted, reason = await rate_limit_service.is_ip_blacklisted(
                ip=client_ip,  # Changed from 'ip' to 'ip_address'
                db_fetch_func=crud_activity.check_ip_blacklisted,
                db=db,
                ip_address=client_ip,
            )

            if is_blacklisted:
                return JSONResponse(
                    status_code=403,
                    content={"detail": reason or "Access denied"}
                )

            # User-based rate limiting
            if user_id:
                user_allowed = await rate_limit_service.check_limit(
                    key=f"user:{user_id}:{path}",
                    max_requests=settings.activity_RATE_LIMIT_USER_MAX_REQUESTS,
                    window_seconds=settings.activity_RATE_LIMIT_USER_WINDOW_SECONDS,
                    clickhouse_db=clickhouse_db,
                    record_type="user",
                    record_data={"user_id": user_id, "path": path},
                )

                if not user_allowed:
                    # Store persistent rate limit in MongoDB
                    asyncio.create_task(crud_rate_limit.set_user_rate_limited(
                        db=db,
                        user_id=user_id,
                        reason=f"User rate limit exceeded for {path}",
                        duration_minutes=10
                    ))

                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Too many requests - please slow down"}
                    )

            # Endpoint-specific rate limiting
            endpoint_config = await rate_limit_service.get_cached_config(
                endpoint=path,
                db_fetch_func=crud_rate_limit.get_rate_limit_config,
                db=db,
            )

            if endpoint_config:
                max_requests = endpoint_config.get("max_requests", 100)
                window_seconds = endpoint_config.get("window_seconds", 60)

                endpoint_allowed = await rate_limit_service.check_limit(
                    key=f"endpoint:{path}:{client_ip}",
                    max_requests=max_requests,
                    window_seconds=window_seconds,
                    clickhouse_db=clickhouse_db,
                    record_type="endpoint",
                    record_data={"ip": client_ip, "path": path}
                )

                if not endpoint_allowed:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": f"Rate limit exceeded for {path}"}
                    )

        except Exception as e:
            # Log the error but allow the request to continue to avoid blocking legitimate requests
            logger.error(f"Error in rate limiting checks: {str(e)}")

        # Process the request if rate limits are not exceeded or there was an error
        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP from request headers"""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Get the first IP if multiple are provided
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
