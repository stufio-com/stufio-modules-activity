import asyncio
import inspect
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging
from fastapi.responses import JSONResponse

from stufio.api import deps
from stufio.db.clickhouse import ClickhouseDatabase
from stufio.core.config import get_settings
from stufio.api.deps import get_db
from ..crud.crud_rate_limit import crud_rate_limit

settings = get_settings()
logger = logging.getLogger(__name__)

# In-memory cache for rate limit decisions with TTLs
# Structure: {key: (is_allowed, expire_timestamp)}
RATE_LIMIT_CACHE = {}
CACHE_TTL_SECONDS = 10  # Cache decisions for 10 seconds

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
            
            now = time.time()
            
            # Check if user is already rate limited in MongoDB
            if user_id:
                is_limited, reason = await crud_rate_limit.is_user_rate_limited(db=db, user_id=user_id)
                if is_limited:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": reason or "Rate limited"}
                    )
            
            # Perform quick cache check first for IP
            ip_cache_key = f"ip:{client_ip}"
            ip_decision = RATE_LIMIT_CACHE.get(ip_cache_key)
            if ip_decision and ip_decision[1] > now:
                # Cache hit and still valid
                if not ip_decision[0]:  # Not allowed
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Too many requests from this IP address"}
                    )
            else:
                # 1. IP-based rate limiting (prevents DDoS)
                ip_allowed = await crud_rate_limit.check_ip_limit(
                    clickhouse_db=clickhouse_db,
                    ip=client_ip,
                    max_requests=settings.RATE_LIMIT_IP_MAX_REQUESTS,
                    window_seconds=settings.RATE_LIMIT_IP_WINDOW_SECONDS
                )
                
                # Add to cache with TTL
                RATE_LIMIT_CACHE[ip_cache_key] = (ip_allowed, now + CACHE_TTL_SECONDS)
                
                if not ip_allowed:
                    # Run this in background task
                    asyncio.create_task(crud_rate_limit.set_user_rate_limited(
                        db=db,
                        user_id=user_id if user_id else f"ip:{client_ip}",
                        reason="IP-based rate limit exceeded",
                        duration_minutes=15
                    ))
                    
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Too many requests from this IP address"}
                    )
                
                # Update counts in background task
                asyncio.create_task(
                    crud_rate_limit.update_ip_request_count(
                        clickhouse_db=clickhouse_db,
                        ip=client_ip
                    )
                )

            # 2. User-based rate limiting (if authenticated)
            if user_id:
                user_cache_key = f"user:{user_id}:{path}"
                user_decision = RATE_LIMIT_CACHE.get(user_cache_key)
                
                if user_decision and user_decision[1] > now:
                    # Cache hit and still valid
                    if not user_decision[0]:  # Not allowed
                        return JSONResponse(
                            status_code=429,
                            content={"detail": "Too many requests - please slow down"}
                        )
                else:
                    # Check user limit
                    user_allowed = await crud_rate_limit.check_user_limit(
                        clickhouse_db=clickhouse_db,
                        user_id=str(user_id),
                        path=path,
                        max_requests=settings.RATE_LIMIT_USER_MAX_REQUESTS,
                        window_seconds=settings.RATE_LIMIT_USER_WINDOW_SECONDS
                    )
                    
                    # Add to cache with TTL
                    RATE_LIMIT_CACHE[user_cache_key] = (user_allowed, now + CACHE_TTL_SECONDS)
                    
                    if not user_allowed:
                        # Set persistent rate limit in background
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
                    
                    # Update counts in background task
                    asyncio.create_task(
                        crud_rate_limit.update_user_request_count(
                            clickhouse_db=clickhouse_db,
                            user_id=str(user_id),
                            path=path
                        )
                    )

            # 3. Endpoint-specific rate limiting (from MongoDB)
            endpoint_cache_key = f"endpoint:{path}:{client_ip}"
            endpoint_decision = RATE_LIMIT_CACHE.get(endpoint_cache_key)
            
            # Get endpoint config (can be cached too for better performance)
            endpoint_config = await crud_rate_limit.get_rate_limit_config(
                db, endpoint=path
            )
            
            # Apply endpoint-specific rate limiting if configured
            if endpoint_config:
                max_requests = endpoint_config.get("max_requests", 100)
                window_seconds = endpoint_config.get("window_seconds", 60)
                
                if endpoint_decision and endpoint_decision[1] > now:
                    # Cache hit and still valid
                    if not endpoint_decision[0]:  # Not allowed
                        return JSONResponse(
                            status_code=429,
                            content={"detail": f"Rate limit exceeded for {path}"}
                        )
                else:
                    # Check endpoint limit
                    endpoint_allowed = await crud_rate_limit.check_endpoint_limit(
                        clickhouse_db=clickhouse_db,
                        path=path,
                        client_ip=client_ip,
                        max_requests=max_requests,
                        window_seconds=window_seconds
                    )
                    
                    # Add to cache with TTL
                    RATE_LIMIT_CACHE[endpoint_cache_key] = (endpoint_allowed, now + CACHE_TTL_SECONDS)
                    
                    if not endpoint_allowed:
                        return JSONResponse(
                            status_code=429,
                            content={"detail": f"Rate limit exceeded for {path}"}
                        )
                    
                    # Update counts in background task
                    asyncio.create_task(
                        crud_rate_limit.update_endpoint_request_count(
                            clickhouse_db=clickhouse_db,
                            path=path,
                            client_ip=client_ip
                        )
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
