import logging
import asyncio
from time import time
from typing import Optional, Dict, Any, Tuple
import json

from stufio.core.config import get_settings
from stufio.db.redis import RedisClient
from stufio.db.mongo import MongoJSONEncoder, serialize_mongo_doc
from ..crud.crud_rate_limit import crud_rate_limit

settings = get_settings()
logger = logging.getLogger(__name__)


class RateLimitService:
    """Service for handling rate limiting with Redis + ClickHouse"""

    @staticmethod
    async def check_limit(
        key: str,
        max_requests: int,
        window_seconds: int,
        record_type=None,
        record_data=None
    ) -> bool:
        """
        Check if a rate limit is exceeded and record in background
        
        Args:
            key: Unique identifier (e.g., "ip:192.168.1.1" or "user:123:path")
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds
            record_type: Type of record (ip, user, endpoint)
            record_data: Additional data to record
            
        Returns:
            bool: True if request should be allowed, False if rate limited
        """

        PREFIX_DISALLOWED = "D"
        PREFIX_ALLOWED = "A"
        CACHE_TTL = settings.activity_RATE_LIMIT_DECISION_TTL
        redis_client = await RedisClient()
        now = time()

        # Create Redis key with proper prefix and namespace
        redis_key = f"{settings.activity_RATE_LIMIT_REDIS_PREFIX}check:{key}"

        is_allowed = None

        # Try to get cached decision
        cached_value = await redis_client.get(redis_key)
        if cached_value:
            if cached_value.startswith(PREFIX_DISALLOWED + ":"):
                try:
                    block_until = float(cached_value.split(":", 1)[1])
                    # If block is still active
                    if block_until > now:
                        is_allowed = False
                except:
                    pass
            elif cached_value == PREFIX_ALLOWED:
                is_allowed = True

        if record_type and record_data:
            # Record analytics in background
            asyncio.create_task(
                RateLimitService._record_analytics(
                    record_type=record_type,
                    record_data=record_data,
                    max_requests=max_requests,
                    window_seconds=window_seconds
                )
            )

            # Cache the result in Redis
        try:
            if is_allowed == True:
                # Cache a "pass" result for 20 seconds
                await redis_client.set(redis_key, PREFIX_ALLOWED, ex=CACHE_TTL)
            elif is_allowed == None:
                if record_type and record_data:
                    is_allowed = await RateLimitService._check_limit(
                        record_type=record_type,
                        record_data=record_data,
                        window_seconds=window_seconds
                    )
                    if is_allowed:
                        # Cache an "allow" result for X seconds
                        await redis_client.set(redis_key, PREFIX_ALLOWED, ex=CACHE_TTL)
                    elif is_allowed == False:
                        # Cache a "block" result for {window_seconds} seconds
                        await redis_client.set(
                            redis_key,
                            f"{PREFIX_DISALLOWED}:{now + window_seconds}",
                            ex=window_seconds,
                        )
                    else:
                        # impossible to check limit
                        logger.warning(f"Can't check rate limit for key {key}")    
                        is_allowed = True
            else:
                # do nothing if already blocked
                pass
        except Exception as e:
            logger.error(f"Error caching rate limit decision in Redis: {str(e)}")

        return is_allowed if is_allowed is not None else True

    @staticmethod
    async def warm_config_cache(
        db_fetch_func,
        **fetch_params
    ) -> None:
        """
        Initialize and warm up the rate limit configuration cache
        
        Args:
            db_fetch_func: Function to call to fetch configurations
            fetch_params: Additional parameters to pass to db_fetch_func
        """
        try:
            # Fetch all configurations
            configs = await db_fetch_func(**fetch_params)

            if not configs:
                logger.warning("No rate limit configurations found to cache")
                return

            redis_client = await RedisClient()

            # Cache each configuration
            for config in configs:
                try:
                    if hasattr(config, "__dict__"):
                        # Handle objects like RateLimitConfigResponse
                        config_dict = config.__dict__
                    elif not isinstance(config, dict):
                        # Convert to dict if it's a model instance
                        config_dict = serialize_mongo_doc(config)
                    else:
                        config_dict = config

                    endpoint = config_dict.get("endpoint")
                    if not endpoint:
                        continue

                    # Create Redis key
                    redis_key = f"{settings.activity_RATE_LIMIT_REDIS_PREFIX}config:{endpoint}"

                    # Serialize and cache using the custom encoder to handle datetime objects
                    config_json = json.dumps(config_dict, cls=MongoJSONEncoder)
                    await redis_client.set(redis_key, config_json)
                    await redis_client.expire(redis_key, settings.activity_RATE_LIMIT_CONFIG_TTL)
                except Exception as e:
                    logger.error(f"Error caching config for endpoint: {e}")
                    continue

            logger.info(f"Cached {len(configs)} rate limit configurations")

        except Exception as e:
            logger.error(f"Error warming rate limit config cache: {str(e)}")

    @staticmethod
    async def _record_analytics(
        record_type,
        record_data,
        max_requests,
        window_seconds
    ) -> None:
        """Record analytics and violations in ClickHouse"""
        try:
            # Use appropriate method based on record type
            if record_type == "ip":
                await crud_rate_limit.update_ip_request_count(
                    ip=record_data.get("ip"),
                    max_requests=max_requests,
                    window_seconds=window_seconds
                )

            elif record_type == "user":
                await crud_rate_limit.update_user_request_count(
                    user_id=record_data.get("user_id"),
                    path=record_data.get("path"),
                    max_requests=max_requests,
                    window_seconds=window_seconds
                )

            elif record_type == "endpoint":
                await crud_rate_limit.update_endpoint_request_count(
                    path=record_data.get("path"),
                    client_ip=record_data.get("ip"),
                    max_requests=max_requests,
                    window_seconds=window_seconds
                )

        except Exception as e:
            logger.error(f"Error recording rate limit analytics: {e}")

    @staticmethod
    async def _check_limit(record_type, record_data, window_seconds) -> Optional[bool]:
        """Record analytics and violations in ClickHouse"""
        try:
            # Use appropriate method based on record type
            if record_type == "ip":
                return await crud_rate_limit.check_ip_limit(
                    ip=record_data.get("ip"),
                    window_seconds=window_seconds
                )

            elif record_type == "user":
                return await crud_rate_limit.check_user_limit(
                    user_id=record_data.get("user_id"),
                    path=record_data.get("path"),
                    window_seconds=window_seconds,
                )

            elif record_type == "endpoint":
                return await crud_rate_limit.check_endpoint_limit(
                    path=record_data.get("path"),
                    client_ip=record_data.get("ip"),
                    window_seconds=window_seconds,
                )

        except Exception as e:
            logger.error(f"Error recording rate limit analytics: {e}")

        return None

    @staticmethod
    async def get_cached_config(
        endpoint: str,
        db_fetch_func,
        **fetch_params
    ) -> Dict[str, Any]:
        """
        Get cached endpoint configuration or fetch from database
        
        Args:
            endpoint: API endpoint path
            db_fetch_func: Function to call if cache misses
            fetch_params: Parameters to pass to db_fetch_func
            
        Returns:
            dict: Endpoint configuration
        """
        redis_client = await RedisClient()
        redis_key = f"{settings.activity_RATE_LIMIT_REDIS_PREFIX}config:{endpoint}"

        # Try to get from cache
        cached = await redis_client.get(redis_key)
        if cached:
            try:
                # Parse the JSON string directly instead of using json module
                return json.loads(cached)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in Redis cache for {endpoint}")

        if "endpoint" not in fetch_params:
            fetch_params["endpoint"] = endpoint

        # Fetch from database
        config = await db_fetch_func(**fetch_params)

        # Cache the result
        if config:
            try:
                # Use the utility function to make the config serializable
                if hasattr(config, "__dict__"):
                    # Handle objects like RateLimitConfigResponse
                    serializable_config = config.__dict__
                else:
                    # Convert to dict if it's a model instance
                    serializable_config = serialize_mongo_doc(config)

                # Then serialize to JSON using the custom encoder
                config_json = json.dumps(serializable_config, cls=MongoJSONEncoder)
                await redis_client.set(redis_key, config_json)
                await redis_client.expire(redis_key, settings.activity_RATE_LIMIT_CONFIG_TTL)
            except Exception as e:
                logger.error(f"Error caching config in Redis: {str(e)}")

        return config

    @staticmethod
    async def is_ip_blacklisted(
        ip: str,
        db_fetch_func=None,
        **fetch_params
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP is blacklisted, with Redis cache and violation records
        """
        redis_client = await RedisClient()

        # Check blacklist cache
        blacklist_key = f"{settings.activity_RATE_LIMIT_REDIS_PREFIX}blacklist:ip:{ip}"
        cached = await redis_client.get(blacklist_key)
        if cached:
            return True, cached

        # Also check violation records
        violation_key = f"{settings.activity_RATE_LIMIT_REDIS_PREFIX}violation:ip:{ip}"
        violation = await redis_client.get(violation_key)
        if violation:
            return True, violation

        # Not in Redis, check database if function provided
        if db_fetch_func:
            is_blacklisted, reason = await db_fetch_func(**fetch_params)

            # Add to cache if blacklisted
            if is_blacklisted:
                await RateLimitService.blacklist_ip(
                    ip=ip,
                    reason=reason or "IP blacklisted",
                    duration_seconds=settings.activity_IP_BLACKLIST_TTL,
                    redis_client=redis_client
                )

            return is_blacklisted, reason

        return False, None

    @staticmethod
    async def blacklist_ip(
        ip: str,
        reason: str = "IP blacklisted",
        duration_seconds: Optional[int] = None,
        redis_client=None,
    ) -> bool:
        """
        Add an IP to the blacklist cache
        
        Args:
            ip: IP address to blacklist
            reason: Reason for blacklisting
            duration_seconds: Time to keep in blacklist (None for permanent)
            
        Returns:
            bool: Success status
        """
        if not redis_client:
            redis_client = await RedisClient()
        redis_key = f"{settings.activity_RATE_LIMIT_REDIS_PREFIX}violation:ip:{ip}"

        # Set expiration or use default
        expiration = duration_seconds or settings.activity_IP_BLACKLIST_TTL

        # Add to Redis
        await redis_client.set(redis_key, reason, ex=expiration)
        return True


# Create singleton instance
rate_limit_service = RateLimitService()
