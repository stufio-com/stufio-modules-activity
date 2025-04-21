import asyncio
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp
import logging
from typing import Tuple, Optional, Dict, Any, List

# Import the base middleware from events module
from stufio.modules.events import BaseStufioMiddleware

from stufio.api import deps
from stufio.core.config import get_settings
from ..crud import crud_rate_limit, crud_activity
from ..services.rate_limit import rate_limit_service


settings = get_settings()
logger = logging.getLogger(__name__)


class RateLimitingMiddleware(BaseStufioMiddleware):
    """
    Middleware for rate limiting requests based on IP, user, and endpoints.
    
    This middleware checks multiple rate limits:
    1. IP-based rate limiting
    2. User-based rate limiting
    3. Endpoint-specific rate limiting
    4. IP blacklist checking
    
    Rate limit data is stored in Redis for fast checks and in MongoDB for persistent storage.
    """
    def __init__(
        self, 
        app: ASGIApp,
        excluded_paths: Optional[List[str]] = None
    ):
        # Define additional paths to exclude from rate limiting
        rate_limit_excluded = [
            settings.API_V1_STR + "/docs",
            settings.API_V1_STR + "/openapi.json",
        ]
        
        # Combine with default excluded paths from base middleware
        if excluded_paths:
            excluded_paths.extend(rate_limit_excluded)
        else:
            excluded_paths = rate_limit_excluded
            
        super().__init__(app, excluded_paths=excluded_paths)
        
        # Initialize and pre-warm the cache
        asyncio.create_task(self._init_rate_limit_cache())
    
    async def _init_rate_limit_cache(self):
        """Initialize and warm up the rate limit cache."""
        try:
            # Pre-fetch common endpoint configurations
            await rate_limit_service.warm_config_cache(
                db_fetch_func=crud_rate_limit.get_all_rate_limit_configs
            )
            logger.info("Rate limit configuration cache initialized")
        except Exception as e:
            logger.error(f"Error initializing rate limit cache: {e}")

    async def _pre_process(self, request: Request) -> None:
        """
        Check rate limits before processing the request.
        
        This method is called by the base middleware's dispatch method
        before the request is processed by the next middleware or route handler.
        """
        # Extract basic request info
        path = request.url.path
        normalized_path = self._normalize_path(path)
        client_ip = self._get_client_ip(request)
        
        # Get current user if authenticated
        user_id = None
        auth_header = request.headers.get("authorization")
        if (
            auth_header
            and auth_header.startswith("Bearer ")
            and path not in [settings.API_V1_STR + "/login/claim"]
        ):
            token = auth_header.replace("Bearer ", "")
            try:
                token_data = deps.get_token_payload(token)
                user_id = token_data.sub
            except Exception as e:
                logger.debug(f"Error extracting user from token: {e}")

        # Check if user is already rate limited in MongoDB
        if user_id:
            is_limited, reason = await crud_rate_limit.is_user_rate_limited(user_id)
            if is_limited:
                raise RateLimitException(
                    detail=reason or "Rate limited",
                    rate_limit_type="user_persistent"
                )

        # IP blacklist check
        is_blacklisted, reason = await rate_limit_service.is_ip_blacklisted(
            ip=client_ip,
            db_fetch_func=crud_activity.check_ip_blacklisted,
            ip_address=client_ip  # Add the missing ip_address parameter here
        )

        if is_blacklisted:
            raise RateLimitException(
                detail=reason or "Access denied",
                rate_limit_type="ip_blacklist"
            )

        # IP-based rate limiting with Redis
        ip_allowed = await rate_limit_service.check_limit(
            key=f"ip:{client_ip}",
            max_requests=settings.activity_RATE_LIMIT_IP_MAX_REQUESTS,
            window_seconds=settings.activity_RATE_LIMIT_IP_WINDOW_SECONDS,
            record_type="ip",
            record_data={"ip": client_ip},
        )

        if not ip_allowed:
            # Store persistent rate limit in MongoDB
            asyncio.create_task(crud_rate_limit.set_user_rate_limited(
                user_id=f"ip:{client_ip}",
                reason="IP-based rate limit exceeded",
                duration_minutes=15
            ))

            raise RateLimitException(
                detail="Too many requests from this IP address",
                rate_limit_type="ip"
            )

        # User-based rate limiting with Redis
        if user_id:
            user_allowed = await rate_limit_service.check_limit(
                key=f"user:{user_id}:{normalized_path}",
                max_requests=settings.activity_RATE_LIMIT_USER_MAX_REQUESTS,
                window_seconds=settings.activity_RATE_LIMIT_USER_WINDOW_SECONDS,
                record_type="user",
                record_data={"user_id": user_id, "path": normalized_path},
            )

            if not user_allowed:
                # Store persistent rate limit in MongoDB
                asyncio.create_task(crud_rate_limit.set_user_rate_limited(
                    user_id=user_id,
                    reason=f"User rate limit exceeded for {normalized_path}",
                    duration_minutes=10
                ))

                raise RateLimitException(
                    detail="Too many requests - please slow down",
                    rate_limit_type="user"
                )

        # Endpoint-specific rate limiting with Redis
        endpoint_config = await rate_limit_service.get_cached_config(
            endpoint=normalized_path,
            db_fetch_func=crud_rate_limit.get_rate_limit_config,
        )

        if endpoint_config:
            max_requests = endpoint_config.get("max_requests", 100)
            window_seconds = endpoint_config.get("window_seconds", 60)

            endpoint_allowed = await rate_limit_service.check_limit(
                key=f"endpoint:{normalized_path}:{client_ip}",
                max_requests=max_requests,
                window_seconds=window_seconds,
                record_type="endpoint",
                record_data={"ip": client_ip, "path": normalized_path}
            )

            if not endpoint_allowed:
                raise RateLimitException(
                    detail=f"Rate limit exceeded for {normalized_path}",
                    rate_limit_type="endpoint"
                )

    async def _handle_exception(self, request: Request, exception: Exception) -> Response:
        """
        Handle exceptions raised during request processing.
        
        This middleware specifically handles RateLimitException and generates
        appropriate responses. Other exceptions are delegated to the base middleware.
        """
        if isinstance(exception, RateLimitException):
            # Return a 429 Too Many Requests response for rate limit exceptions
            rate_limit_type = getattr(exception, "rate_limit_type", "unknown")
            
            # Add rate limit headers
            headers = {
                "X-Rate-Limit-Type": rate_limit_type,
                "Retry-After": "60",  # Default retry after 60 seconds
            }
            
            # For different rate limit types, set different retry periods
            if rate_limit_type == "ip_blacklist":
                headers["Retry-After"] = str(24 * 60 * 60)  # 24 hours
            elif rate_limit_type == "user_persistent":
                headers["Retry-After"] = str(10 * 60)  # 10 minutes
            
            return JSONResponse(
                status_code=429,
                content={"detail": str(exception)},
                headers=headers
            )
        
        # For other exceptions, delegate to the base middleware
        return await super()._handle_exception(request, exception)


class RateLimitException(Exception):
    """Custom exception for rate limiting."""
    def __init__(self, detail: str, rate_limit_type: str = "unknown"):
        self.detail = detail
        self.rate_limit_type = rate_limit_type
        super().__init__(detail)
