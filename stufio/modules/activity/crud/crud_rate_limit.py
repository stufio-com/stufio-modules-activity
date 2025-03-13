import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from motor.core import AgnosticDatabase
from bson import ObjectId
from clickhouse_connect.driver.asyncclient import AsyncClient
from stufio.crud.clickhouse_base import CRUDClickhouseBase
from stufio.crud.mongo_base import CRUDMongoBase
from ..models import (
    RateLimitOverride,
    RateLimit,
)
from ..schemas import RateLimitStatus, ViolationReport, RateLimitConfigResponse
from stufio.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


class CRUDRateLimit(
    CRUDMongoBase[RateLimit, None, None], CRUDClickhouseBase[RateLimit, None, None]
):
    """CRUD operations for rate limits and overrides"""

    async def check_and_update_ip_limit(
        self,
        db: AgnosticDatabase,
        clickhouse_db: AsyncClient,
        ip: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """
        Check if IP has exceeded rate limit.
        Returns True if request is allowed, False if rate limit exceeded.
        """
        # First check if IP is blacklisted
        blacklisted = await db.ip_blacklist.find_one({"ip": ip})
        if blacklisted:
            return False

        key = f"ip:{ip}"
        return await self._check_and_update_limit(
            clickhouse_db=clickhouse_db,
            db=db,
            key=key,
            type="ip",
            max_requests=max_requests,
            window_seconds=window_seconds,
            ip=ip
        )

    async def check_and_update_user_limit(
        self,
        db: AgnosticDatabase,
        clickhouse_db: AsyncClient,
        user_id: str,
        path: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """
        Check if user has exceeded rate limit for a specific path.
        Returns True if request is allowed, False if rate limit exceeded.
        """
        # First, check for any overrides for this user
        override = await self._get_user_override(db, user_id=user_id, path=path)
        if override:
            # Use override values if not expired
            now = datetime.utcnow()
            if override.get("expires_at") and override.get("expires_at") < now:
                # Override expired, delete it
                await db.rate_limit_overrides.delete_one({"_id": override["_id"]})
            else:
                # Use override values
                max_requests = override.get("max_requests", max_requests)
                window_seconds = override.get("window_seconds", window_seconds)

        key = f"user:{user_id}:{path}"
        return await self._check_and_update_limit(
            clickhouse_db=clickhouse_db,
            db=db, 
            key=key,
            type="user",
            max_requests=max_requests,
            window_seconds=window_seconds,
            user_id=user_id,
            endpoint=path
        )

    async def check_and_update_endpoint_limit(
        self,
        db: AgnosticDatabase,
        clickhouse_db: AsyncClient,
        endpoint: str,
        client_ip: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """
        Check if endpoint+IP has exceeded rate limit.
        Returns True if request is allowed, False if rate limit exceeded.
        """
        key = f"endpoint:{endpoint}:ip:{client_ip}"
        return await self._check_and_update_limit(
            clickhouse_db=clickhouse_db,
            db=db,
            key=key,
            type="endpoint",
            max_requests=max_requests,
            window_seconds=window_seconds,
            ip=client_ip,
            endpoint=endpoint
        )

    async def _check_and_update_limit(
        self,
        clickhouse_db: AsyncClient,
        db: AgnosticDatabase,
        key: str,
        type: str,
        max_requests: int,
        window_seconds: int,
        ip: Optional[str] = None,
        user_id: Optional[str] = None,
        endpoint: Optional[str] = None
    ) -> bool:
        """Core rate limiting logic using ClickHouse"""
        try:
            now = datetime.utcnow()
            window_start = now - timedelta(seconds=window_seconds)

            # Query existing requests in this time window - FIXED PARAMETER SYNTAX
            result = await clickhouse_db.query(
                """
                SELECT sum(counter) as total_count
                FROM rate_limits
                WHERE key = %(key)s AND window_start >= %(window_start)s
                """,
                parameters={
                    "key": key,
                    "window_start": window_start
                }
            )

            # Get total count from result
            total_count = result.first_row[0] if result.row_count > 0 else 0

            # Check if limit exceeded
            if total_count >= max_requests:
                # Record violation for analytics
                await self._record_violation(
                    clickhouse_db=clickhouse_db,
                    key=key,
                    type=type,
                    limit=max_requests,
                    attempts=total_count + 1,  # Including this attempt
                    ip=ip,
                    user_id=user_id,
                    endpoint=endpoint
                )
                return False

            # Record this request
            window_end = now + timedelta(seconds=window_seconds)

            data = {
                "timestamp": now,
                "date": now.replace(hour=0, minute=0, second=0, microsecond=0),
                "key": key,
                "type": type,
                "counter": 1,
                "window_start": now,
                "window_end": window_end,
                "ip": ip,
                "user_id": user_id,
                "endpoint": endpoint
            }

            # Insert request into ClickHouse
            await clickhouse_db.insert(
                'rate_limits',
                [list(data.values())],
                column_names=list(data.keys())
            )

            return True
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            # In case of error, allow the request to proceed
            # This is safer than accidentally blocking legitimate requests
            return True

    async def get_user_limit_status(
        self,
        db: AgnosticDatabase,
        clickhouse_db: AsyncClient,
        user_id: str,
        path: str,
        max_requests: int,
        window_seconds: int
    ) -> RateLimitStatus:
        """
        Get current rate limit status for user.
        Returns remaining requests and reset time.
        """
        try:
            # Check for override
            override = await self._get_user_override(db, user_id=user_id, path=path)
            if override:
                now = datetime.utcnow()
                if override.get("expires_at") and override.get("expires_at") < now:
                    # Override expired, delete it
                    await db.rate_limit_overrides.delete_one({"_id": override["_id"]})
                else:
                    # Use override values
                    max_requests = override.get("max_requests", max_requests)
                    window_seconds = override.get("window_seconds", window_seconds)

            key = f"user:{user_id}:{path}"
            now = datetime.utcnow()
            window_start = now - timedelta(seconds=window_seconds)

            # Query total requests in current window
            result = await clickhouse_db.query(
                """
                SELECT sum(counter) as total_count,
                       max(window_end) as latest_expiry
                FROM rate_limits
                WHERE key = {key} AND window_start >= {window_start}
                """,
                parameters={
                    "key": key,
                    "window_start": window_start
                }
            )

            total_count = result.first_row[0] if result.row_count > 0 else 0
            reset_at = result.first_row[1] if result.row_count > 0 and result.first_row[1] else now + timedelta(seconds=window_seconds)

            # Calculate remaining requests
            remaining = max(0, max_requests - total_count)

            return RateLimitStatus(
                total_allowed=max_requests,
                remaining=remaining,
                reset_at=reset_at,
                window_seconds=window_seconds
            )
        except Exception as e:
            logger.error(f"Error getting user limit status: {str(e)}")
            # Return a default status in case of error
            return RateLimitStatus(
                total_allowed=max_requests,
                remaining=max_requests,
                reset_at=datetime.utcnow() + timedelta(seconds=window_seconds),
                window_seconds=window_seconds
            )

    async def _record_violation(
        self,
        clickhouse_db: AsyncClient,
        key: str,
        type: str,
        limit: int,
        attempts: int,
        ip: Optional[str] = None,
        user_id: Optional[str] = None,
        endpoint: Optional[str] = None
    ) -> None:
        """Record a rate limit violation in ClickHouse for analysis"""
        try:
            now = datetime.utcnow()

            data = {
                "timestamp": now,
                "date": now.replace(hour=0, minute=0, second=0, microsecond=0),
                "key": key,
                "type": type,
                "limit": limit,
                "attempts": attempts,
                "user_id": user_id,
                "client_ip": ip,
                "endpoint": endpoint
            }

            # Insert violation record
            await clickhouse_db.insert(
                'rate_limit_violations',
                [list(data.values())],
                column_names=list(data.keys())
            )
        except Exception as e:
            # Just log the error, don't let this affect the main flow
            logger.error(f"Failed to record rate limit violation: {str(e)}")

    async def _get_user_override(
        self,
        db: AgnosticDatabase,
        user_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """Get rate limit override for user if exists"""
        # First try exact path match
        override = await db.rate_limit_overrides.find_one({
            "user_id": user_id,
            "path": path
        })

        if override:
            return override

        # Then try wildcard match
        override = await db.rate_limit_overrides.find_one({
            "user_id": user_id,
            "path": "*"
        })

        return override

    async def create_user_override(
        self,
        db: AgnosticDatabase,
        user_id: str,
        path: str,
        max_requests: int,
        window_seconds: int,
        expires_at: Optional[datetime] = None,
        created_by: Optional[str] = None,
        reason: Optional[str] = None
    ) -> RateLimitOverride:
        """Create or update a rate limit override for a user"""
        # Check if override already exists
        existing = await db.rate_limit_overrides.find_one({
            "user_id": user_id,
            "path": path
        })

        now = datetime.utcnow()
        override_data = {
            "user_id": user_id,
            "path": path,
            "max_requests": max_requests,
            "window_seconds": window_seconds,
            "created_at": now,
            "expires_at": expires_at,
            "created_by": created_by,
            "reason": reason
        }

        if existing:
            # Update existing override
            await db.rate_limit_overrides.update_one(
                {"_id": existing["_id"]},
                {"$set": override_data}
            )
            override_id = str(existing["_id"])
        else:
            # Create new override
            result = await db.rate_limit_overrides.insert_one(override_data)
            override_id = str(result.inserted_id)

        # Return the complete override
        return RateLimitOverride(
            id=override_id,
            user_id=user_id,
            path=path,
            max_requests=max_requests,
            window_seconds=window_seconds,
            created_at=now,
            expires_at=expires_at,
            created_by=created_by,
            reason=reason
        )

    async def get_overrides(
        self,
        db: AgnosticDatabase,
        user_id: Optional[str] = None
    ) -> List[RateLimitOverride]:
        """Get all rate limit overrides, optionally filtered by user_id"""
        query = {}
        if user_id:
            query["user_id"] = user_id

        overrides = await db.rate_limit_overrides.find(query).to_list(length=1000)

        # Convert to model objects
        result = []
        for override in overrides:
            override_dict = {k: v for k, v in override.items() if k != '_id'}
            override_dict['id'] = str(override['_id'])
            result.append(RateLimitOverride(**override_dict))

        return result

    async def delete_override(
        self,
        db: AgnosticDatabase,
        override_id: str
    ) -> bool:
        """Delete a rate limit override"""
        try:
            object_id = ObjectId(override_id)
        except:
            return False

        result = await db.rate_limit_overrides.delete_one({"_id": object_id})
        return result.deleted_count > 0

    async def get_violations(
        self,
        clickhouse_db: AsyncClient,
        skip: int = 0,
        limit: int = 50,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        type: Optional[str] = None,
    ) -> List[ViolationReport]:
        """Get recent rate limit violations from ClickHouse"""
        try:
            where_clauses = []
            params = {}

            # Add date range filter if provided
            if start_date:
                where_clauses.append("date >= {start_date}")
                params["start_date"] = start_date.date()
            else:
                # Default to last 7 days
                where_clauses.append("date >= today() - 7")

            if end_date:
                where_clauses.append("date <= {end_date}")
                params["end_date"] = end_date.date()

            # Add type filter if provided
            if type:
                where_clauses.append("type = {type}")
                params["type"] = type

            # Combine all WHERE clauses
            where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"

            # Execute query
            result = await clickhouse_db.query(
                f"""
                SELECT
                    timestamp,
                    date,
                    key,
                    type,
                    limit,
                    attempts,
                    user_id,
                    client_ip,
                    endpoint
                FROM rate_limit_violations
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT {limit} OFFSET {skip}
                """,
                parameters=params
            )

            return list([ViolationReport(**row) for row in list(result.named_results())])
        except Exception as e:
            logger.error(f"Error fetching rate limit violations: {str(e)}")
            return []

    async def get_rate_limit_analytics(
        self,
        clickhouse_db: AsyncClient,
        days: int = 7
    ) -> Dict[str, Any]:
        """Get rate limit analytics from ClickHouse"""
        try:
            # Get summary stats
            summary = await clickhouse_db.query(
                """
                SELECT
                    count() AS total_violations,
                    uniq(client_ip) AS unique_ips,
                    uniq(user_id) AS unique_users,
                    uniq(endpoint) AS unique_endpoints,
                    avg(attempts) AS avg_attempts
                FROM rate_limit_violations
                WHERE date >= today() - {days}
                """,
                parameters={"days": days}
            )

            # Get violations by type
            by_type = await clickhouse_db.query(
                """
                SELECT
                    type,
                    count() AS count
                FROM rate_limit_violations
                WHERE date >= today() - {days}
                GROUP BY type
                ORDER BY count DESC
                """,
                parameters={"days": days}
            )

            # Get top offenders (IPs)
            top_ips = await clickhouse_db.query(
                """
                SELECT
                    client_ip,
                    count() AS violations
                FROM rate_limit_violations
                WHERE date >= today() - {days} AND client_ip IS NOT NULL
                GROUP BY client_ip
                ORDER BY violations DESC
                LIMIT 10
                """,
                parameters={"days": days}
            )

            # Get violations by day
            by_day = await clickhouse_db.query(
                """
                SELECT
                    date,
                    count() AS violations
                FROM rate_limit_violations
                WHERE date >= today() - {days}
                GROUP BY date
                ORDER BY date
                """,
                parameters={"days": days}
            )

            return {
                "summary": summary.first_rows_as_dicts()[0] if summary.row_count > 0 else {},
                "by_type": list(by_type.named_results()),
                "top_ips": list(top_ips.named_results()),
                "by_day": list(by_day.named_results())
            }
        except Exception as e:
            logger.error(f"Error getting rate limit analytics: {str(e)}")
            return {
                "summary": {},
                "by_type": [],
                "top_ips": [],
                "by_day": []
            }

            # Add these methods to your existing CRUDRateLimit class

    async def get_rate_limit_config(
        self,
        db: AgnosticDatabase,
        *,
        endpoint: str
    ) -> Optional[Dict[str, Any]]:
        """Get rate limit configuration for an endpoint from MongoDB"""
        # Try prefix matching (for nested endpoints)
        cursor = db.rate_limit_configs.find(
            {"active": True}, {"_id":0, "endpoint": 1}
        ).sort("endpoint", -1)  # Sort by endpoint length descending

        async for cfg in cursor:
            if (cfg["endpoint"][-1:] == '*' and endpoint.startswith(cfg["endpoint"][:-1])) or endpoint == cfg["endpoint"]:
                # Found a matching config
                return cfg

        # No specific config found
        return None

    async def get_all_rate_limit_configs(
        self,
        db: AgnosticDatabase,
        *,
        skip: int = 0,
        limit: int = 100,
        active_only: bool = False,
    ) -> List[RateLimitConfigResponse]:
        """Get all rate limit configurations"""
        query = {"active": True} if active_only else {}
        cursor = db.rate_limit_configs.find(query).sort("endpoint", 1).skip(skip).limit(limit)
        configs = await cursor.to_list(length=limit)

        # Convert ObjectId to string for each document
        for config in configs:
            config["id"] = str(config.pop("_id"))

        return [RateLimitConfigResponse(**config) for config in configs]

    async def create_rate_limit_config(
        self,
        db: AgnosticDatabase,
        *,
        endpoint: str,
        max_requests: int,
        window_seconds: int,
        bypass_roles: List[str] = None,
        description: Optional[str] = None,
        active: bool = True,
    ) -> RateLimitConfigResponse:
        """Create or update a rate limit configuration"""
        now = datetime.utcnow()
        config = {
            "endpoint": endpoint,
            "max_requests": max_requests,
            "window_seconds": window_seconds,
            "active": active,
            "bypass_roles": bypass_roles or [],
            "description": description,
            "created_at": now,
            "updated_at": now
        }

        # Check if config already exists
        existing = await db.rate_limit_configs.find_one(
            {"endpoint": endpoint}
        )

        if existing:
            # Update existing config
            config["created_at"] = existing.get("created_at", now)
            result = await db.rate_limit_configs.update_one(
                {"_id": existing["_id"]},
                {"$set": {**config, "updated_at": now}}
            )
            config["id"] = str(existing["_id"])
        else:
            # Create new config
            result = await db.rate_limit_configs.insert_one(config)
            config["id"] = str(result.inserted_id)

        return RateLimitConfigResponse(**config)

    async def update_rate_limit_config(
        self,
        db: AgnosticDatabase,
        *,
        config_id: str,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None,
        active: Optional[bool] = None,
        bypass_roles: Optional[List[str]] = None,
        description: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Update a rate limit configuration"""
        try:
            object_id = ObjectId(config_id)
        except:
            return None

        update_data = {"updated_at": datetime.utcnow()}

        if max_requests is not None:
            update_data["max_requests"] = max_requests

        if window_seconds is not None:
            update_data["window_seconds"] = window_seconds

        if active is not None:
            update_data["active"] = active

        if bypass_roles is not None:
            update_data["bypass_roles"] = bypass_roles

        if description is not None:
            update_data["description"] = description

        result = await db.rate_limit_configs.update_one(
            {"_id": object_id},
            {"$set": update_data}
        )

        if result.matched_count == 0:
            return None

        # Get updated document
        updated = await db.rate_limit_configs.find_one({"_id": object_id})
        if updated:
            updated["id"] = str(updated.pop("_id"))

        return RateLimitConfigResponse(**updated)

    async def delete_rate_limit_config(
        self,
        db: AgnosticDatabase,
        *,
        config_id: str
    ) -> bool:
        """Delete a rate limit configuration"""
        try:
            object_id = ObjectId(config_id)
        except:
            return False

        result = await db.rate_limit_configs.delete_one({"_id": object_id})
        return result.deleted_count > 0

    async def check_ip_limit(
        self, 
        clickhouse_db: AsyncClient,
        *,
        ip: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """Check if an IP address has exceeded its rate limit using materialized view"""
        try:
            # Use the aggregating table with materialized view
            result = await clickhouse_db.query(
                """
                SELECT countMerge(request_count) as count
                FROM ip_rate_limits
                WHERE ip = {ip:String}
                AND minute >= now() - interval {window:UInt32} second
                """,
                parameters={"ip": ip, "window": window_seconds},
            )
            
            # Process results
            count_results = list(result.named_results())
            count = count_results[0]["count"] if count_results else 0
            
            return count < max_requests
        except Exception as e:
            logger.error(f"Error checking IP rate limit: {str(e)}")
            return True  # Allow if error to prevent false blocks
    
    async def update_ip_request_count(
        self,
        clickhouse_db: AsyncClient,
        *,
        ip: str
    ) -> None:
        """Update IP request count in background (no need to wait for result)"""
        try:
            # ClickHouse materialized view will automatically update based on user_activity table
            # So this function doesn't need to do anything explicit
            # Just log for monitoring purposes
            logger.debug(f"IP {ip} request logged - materialized view will update automatically")
        except Exception as e:
            logger.error(f"Error in background IP tracking: {str(e)}")
    
    async def check_user_limit(
        self,
        clickhouse_db: AsyncClient,
        *,
        user_id: str,
        path: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """Check if a user has exceeded their rate limit for a specific path"""
        try:
            # Use the user-specific materialized view
            result = await clickhouse_db.query(
                """
                SELECT countMerge(request_count) as count
                FROM user_rate_limits
                WHERE user_id = {user_id:String}
                AND path = {path:String}
                AND minute >= now() - interval {window:UInt32} second
                """,
                parameters={"user_id": user_id, "path": path, "window": window_seconds},
            )
            
            count_results = list(result.named_results())
            count = count_results[0]["count"] if count_results else 0
            
            return count < max_requests
        except Exception as e:
            logger.error(f"Error checking user rate limit: {str(e)}")
            return True  # Allow if error

    async def update_user_request_count(
        self,
        clickhouse_db: AsyncClient,
        *,
        user_id: str,
        path: str
    ) -> None:
        """Update user request count in background (no need to wait for result)"""
        try:
            # Materialized view will handle this automatically
            logger.debug(f"User {user_id} request to {path} logged - view will update automatically")
        except Exception as e:
            logger.error(f"Error in background user tracking: {str(e)}")

    async def check_endpoint_limit(
        self,
        clickhouse_db: AsyncClient,
        *,
        path: str,
        client_ip: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """Check if endpoint rate limit has been exceeded"""
        try:
            # Query the endpoint-specific materialized view
            result = await clickhouse_db.query(
                """
                SELECT countMerge(request_count) as count
                FROM endpoint_rate_limits
                WHERE path = {path:String}
                AND client_ip = {ip:String}
                AND minute >= now() - interval {window:UInt32} second
                """,
                parameters={"path": path, "ip": client_ip, "window": window_seconds},
            )
            
            count_results = list(result.named_results())
            count = count_results[0]["count"] if count_results else 0
            
            return count < max_requests
        except Exception as e:
            logger.error(f"Error checking endpoint rate limit: {str(e)}")
            return True

    async def update_endpoint_request_count(
        self,
        clickhouse_db: AsyncClient,
        *,
        path: str,
        client_ip: str
    ) -> None:
        """Update endpoint request count in background"""
        try:
            # Materialized view will handle this automatically
            logger.debug(f"Request to {path} from {client_ip} logged - view will update automatically")
        except Exception as e:
            logger.error(f"Error in background endpoint tracking: {str(e)}")

    async def get_rate_limit_config(self, db: AgnosticDatabase, *, endpoint: str) -> Optional[Dict[str, Any]]:
        """Get rate limit configuration for an endpoint"""
        try:
            # Try to find exact match first
            config = await db.rate_limit_configs.find_one({"endpoint": endpoint, "active": True})
            
            # If no exact match, try to find wildcard match
            if not config:
                # Get global default
                config = await db.rate_limit_configs.find_one({"endpoint": "*", "active": True})
                
            return config
        except Exception as e:
            logger.error(f"Error fetching rate limit config: {str(e)}")
            return None

    # Methods for checking and working with user_rate_limits MongoDB collection
    
    async def set_user_rate_limited(
        self,
        db: AgnosticDatabase,
        *,
        user_id: str,
        reason: str,
        duration_minutes: int = 60
    ) -> bool:
        """Set a user as rate limited in MongoDB"""
        try:
            limited_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
            
            result = await db.user_rate_limits.update_one(
                {"user_id": user_id},
                {
                    "$set": {
                        "is_limited": True,
                        "reason": reason,
                        "limited_until": limited_until,
                        "updated_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            return result.modified_count > 0 or result.upserted_id is not None
        except Exception as e:
            logger.error(f"Error setting user rate limit: {str(e)}")
            return False

    async def remove_user_rate_limit(
        self,
        db: AgnosticDatabase,
        *,
        user_id: str
    ) -> bool:
        """Remove rate limit from a user"""
        try:
            result = await db.user_rate_limits.update_one(
                {"user_id": user_id},
                {
                    "$set": {
                        "is_limited": False,
                        "updated_at": datetime.utcnow()
                    },
                    "$unset": {
                        "reason": "",
                        "limited_until": ""
                    }
                }
            )
            
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error removing user rate limit: {str(e)}")
            return False

    async def is_user_rate_limited(
        self,
        db: AgnosticDatabase,
        *,
        user_id: str
    ) -> Tuple[bool, Optional[str]]:
        """Check if a user is rate limited from MongoDB record"""
        try:
            record = await db.user_rate_limits.find_one({"user_id": user_id})
            if record and record.get("is_limited", False):
                # Check if limitation has expired
                limited_until = record.get("limited_until")
                if limited_until and limited_until > datetime.utcnow():
                    return True, record.get("reason", "Rate limited")
            return False, None
        except Exception as e:
            logger.error(f"Error checking user rate limit status: {str(e)}")
            return False, None


# Create singleton instance
crud_rate_limit = CRUDRateLimit(RateLimit)
