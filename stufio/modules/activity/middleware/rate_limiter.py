import asyncio
import inspect
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging
from fastapi.responses import JSONResponse
from datetime import datetime

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
CACHE_TTL_SECONDS = 30  # Cache decisions for 10 seconds

# Create LRU cache for rate limit config lookups to reduce DB load
ENDPOINT_CONFIG_CACHE = {}  # {endpoint: (config, expire_timestamp)}
ENDPOINT_CACHE_TTL = 120  # 2 minutes

# In-memory cache for blacklisted IPs
# Structure: {ip: (timestamp_added, reason)}
IP_BLACKLIST_CACHE = {}

async def get_cached_rate_limit_config(db, endpoint):
    """Get rate limit config with caching"""
    now = time.time()
    
    # Check cache first
    cached = ENDPOINT_CONFIG_CACHE.get(endpoint)
    if cached and cached[1] > now:
        return cached[0]
    
    # Get from DB if not cached or expired
    config = await crud_rate_limit.get_rate_limit_config(db, endpoint=endpoint)
    
    # Cache the result (even if None)
    ENDPOINT_CONFIG_CACHE[endpoint] = (config, now + ENDPOINT_CACHE_TTL)
    
    return config

async def get_cached_rate_limit_decision(
    cache_key: str,
    check_func,
    **check_params
) -> bool:
    """
    Get a cached rate limit decision or compute and cache a new one.
    
    Args:
        cache_key: Unique cache key for this rate limit decision
        check_func: Async function to call if cache miss (e.g. check_ip_limit)
        **check_params: Parameters to pass to the check function
        
    Returns:
        bool: True if request is allowed, False if it's rate limited
    """
    now = time.time()
    
    # Check cache first for faster response
    cached = RATE_LIMIT_CACHE.get(cache_key)
    if cached and cached[1] > now:
        # Cache hit and still valid
        return cached[0]
    
    # Cache miss or expired - perform the actual check
    is_allowed = await check_func(**check_params)
    
    # Cache the result with TTL
    RATE_LIMIT_CACHE[cache_key] = (is_allowed, now + CACHE_TTL_SECONDS)
    
    # Implement cache cleanup to prevent memory leaks
    if len(RATE_LIMIT_CACHE) > 10000:  # Arbitrary limit
        # Simple cleanup - remove expired entries
        for k in list(RATE_LIMIT_CACHE.keys()):
            if RATE_LIMIT_CACHE[k][1] < now:
                del RATE_LIMIT_CACHE[k]
    
    return is_allowed

async def check_and_update_ip_blacklist(db, ip, clickhouse_db):
    """Check if an IP is blacklisted and update cache in background"""
    try:
        # Check if this IP is already in our blacklist cache
        if ip in IP_BLACKLIST_CACHE:
            return
            
        # Check if IP is in MongoDB blacklist
        now = datetime.utcnow()
        ip_block = await db.ip_blacklist.find_one({
            "ip": ip,
            "$or": [
                {"expires_at": {"$exists": False}},
                {"expires_at": None},
                {"expires_at": {"$gt": now}}
            ]
        })
        
        if ip_block:
            # Add to in-memory cache
            IP_BLACKLIST_CACHE[ip] = (time.time(), ip_block.get("reason", "IP blacklisted"))
            logger.info(f"Added IP {ip} to blacklist cache: {ip_block.get('reason')}")
            
            # Record in ClickHouse for analytics
            await crud_rate_limit._record_violation(
                clickhouse_db=clickhouse_db,
                key=f"blacklist:{ip}",
                type="ip_blacklist",
                limit=0,  # No limit since it's a blacklist
                attempts=1,
                ip=ip,
                user_id=None,
                endpoint=None
            )
    except Exception as e:
        logger.error(f"Error in IP blacklist background check: {str(e)}")

# Add periodic cleanup for IP blacklist cache
async def cleanup_ip_blacklist_cache():
    """Periodically clean up expired entries from IP blacklist cache"""
    try:
        # This is a very simple cleanup - in production you might want a more
        # sophisticated approach with TTL based on the expires_at from MongoDB
        max_age = 24 * 60 * 60  # 24 hours
        now = time.time()
        
        for ip, (timestamp, _) in list(IP_BLACKLIST_CACHE.items()):
            if now - timestamp > max_age:
                del IP_BLACKLIST_CACHE[ip]
    except Exception as e:
        logger.error(f"Error cleaning up IP blacklist cache: {str(e)}")

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
                ip_allowed = await get_cached_rate_limit_decision(
                    cache_key=ip_cache_key,
                    check_func=crud_rate_limit.check_ip_limit,
                    clickhouse_db=clickhouse_db,
                    ip=client_ip,
                    max_requests=settings.RATE_LIMIT_IP_MAX_REQUESTS,
                    window_seconds=settings.RATE_LIMIT_IP_WINDOW_SECONDS
                )
                
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
                        ip=client_ip,
                        max_requests=settings.RATE_LIMIT_IP_MAX_REQUESTS,
                        window_seconds=settings.RATE_LIMIT_IP_WINDOW_SECONDS
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
                    user_allowed = await get_cached_rate_limit_decision(
                        cache_key=user_cache_key,
                        check_func=crud_rate_limit.check_user_limit,
                        clickhouse_db=clickhouse_db,
                        user_id=str(user_id),
                        path=path,
                        max_requests=settings.RATE_LIMIT_USER_MAX_REQUESTS,
                        window_seconds=settings.RATE_LIMIT_USER_WINDOW_SECONDS
                    )
                    
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
                    
                    # Update counts in background task - PASS THE NECESSARY PARAMETERS
                    asyncio.create_task(
                        crud_rate_limit.update_user_request_count(
                            clickhouse_db=clickhouse_db,
                            user_id=str(user_id),
                            path=path,
                            max_requests=settings.RATE_LIMIT_USER_MAX_REQUESTS,
                            window_seconds=settings.RATE_LIMIT_USER_WINDOW_SECONDS
                        )
                    )

            # 3. Endpoint-specific rate limiting (from MongoDB)
            endpoint_cache_key = f"endpoint:{path}:{client_ip}"
            endpoint_decision = RATE_LIMIT_CACHE.get(endpoint_cache_key)
            
            # Get endpoint config (can be cached too for better performance)
            endpoint_config = await get_cached_rate_limit_config(db, endpoint=path)
            
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
                    endpoint_allowed = await get_cached_rate_limit_decision(
                        cache_key=endpoint_cache_key,
                        check_func=crud_rate_limit.check_endpoint_limit,
                        clickhouse_db=clickhouse_db,
                        path=path,
                        client_ip=client_ip,
                        max_requests=max_requests,
                        window_seconds=window_seconds
                    )
                    
                    if not endpoint_allowed:
                        return JSONResponse(
                            status_code=429,
                            content={"detail": f"Rate limit exceeded for {path}"}
                        )
                    
                    # Update counts in background task - PASS THE NECESSARY PARAMETERS
                    asyncio.create_task(
                        crud_rate_limit.update_endpoint_request_count(
                            clickhouse_db=clickhouse_db,
                            path=path,
                            client_ip=client_ip,
                            max_requests=max_requests,
                            window_seconds=window_seconds
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
