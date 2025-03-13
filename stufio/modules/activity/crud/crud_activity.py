from datetime import datetime, timedelta
import hashlib
from typing import List, Optional, Dict, Any, Tuple
from stufio.db.mongo import get_engine
from bson.objectid import ObjectId
from clickhouse_connect.driver.asyncclient import AsyncClient
from ..models import IPBlacklist, SuspiciousActivity, UserActivitySummary, UserActivity, ClientFingerprint, UserSecurityProfile
from ..schemas import TrustedDeviceCreate
from motor.core import AgnosticDatabase
from stufio.crud.clickhouse_base import CRUDClickhouseBase
from stufio.crud.mongo_base import CRUDMongoBase
from stufio.core.config import get_settings
import logging

settings = get_settings()
logger = logging.getLogger(__name__)


class CRUDUserActivity(
    CRUDMongoBase[UserActivity, None, None], CRUDClickhouseBase[UserActivity, None, None]
):

    async def initialize(self):
        """Initialize async resources"""
        # Get the engine for MongoDB
        self.engine = get_engine()
        return self

    async def create_activity(
        self,
        db: AsyncClient,
        *,
        user_id: Optional[str],
        path: str,
        method: str,
        client_ip: str,
        user_agent: str,
        status_code: int,
        process_time: float,
    ) -> bool:
        """
        Record an API request in ClickHouse for analytics

        Args:
            db: ClickHouse connection
            user_id: User ID if authenticated, `{client_id}#{user_agent}` otherwise
            path: API path
            method: HTTP method (GET, POST, etc.)
            client_ip: Client IP address
            user_agent: User agent string
            status_code: HTTP status code
            process_time: Request processing time in seconds
            is_authenticated: Whether the request was authenticated

        Returns:
            bool: Success status
        """
        try:
            # Format timestamp for ClickHouse
            is_authenticated = True if user_id else False
            if not user_id:
                user_id = f"{client_ip}#{user_agent}"

            api_request = UserActivity(
                user_id=user_id,
                path=path,
                method=method,
                client_ip=client_ip,
                user_agent=user_agent,
                status_code=status_code,
                process_time=process_time,
                is_authenticated=is_authenticated,
            )

            # Convert to dict and use for insert
            data = api_request.dict_for_insert()

            await db.insert(
                api_request.get_table_name(),
                [list(data.values())],
                column_names=list(data.keys()),
            )

            # Update user security profile if this is an authenticated user
            if is_authenticated:
                await self._update_user_security_profile(
                    user_id=user_id,
                    client_ip=client_ip,
                    user_agent=user_agent
                )

            return True
        except Exception as e:
            logger.error(f"Error recording API request in ClickHouse: {str(e)}")
            return False

    async def _update_user_security_profile(
        self,
        user_id: str,
        client_ip: str,
        user_agent: str
    ) -> None:
        """Update the user's security profile with this client info"""
        # Get or create security profile
        security_profile = await self.engine.find_one(
            UserSecurityProfile, UserSecurityProfile.user_id == user_id
        )

        if not security_profile:
            security_profile = UserSecurityProfile(
                user_id=user_id,
                known_fingerprints=[
                    ClientFingerprint(
                        ip=client_ip,
                        user_agent=user_agent
                    )
                ]
            )
            await self.engine.save(security_profile)
            return

        # Check if this fingerprint exists
        fingerprint_exists = False
        for fp in security_profile.known_fingerprints:
            if fp.ip == client_ip and fp.user_agent == user_agent:
                # Update existing fingerprint
                fp.last_seen = datetime.utcnow()
                fp.request_count += 1
                fingerprint_exists = True
                break

        if not fingerprint_exists:
            # Add new fingerprint
            security_profile.known_fingerprints.append(
                ClientFingerprint(
                    ip=client_ip,
                    user_agent=user_agent
                )
            )

        await self.engine.save(security_profile)

    async def check_suspicious_activity(
        self,
        clickhouse_db: AsyncClient,
        *,
        user_id: Optional[str],
        client_ip: str,
        user_agent: str,
        path: str,
        method: str,
        status_code: int,
    ) -> bool:
        """
        Check if this activity appears suspicious based on:
        - New IP/device combination
        - Too many different IPs in short time
        - Known suspicious IP addresses
        """
        result = False

        sensitive_paths = [
            settings.API_V1_STR + "/login/*",
            settings.API_V1_STR + "/users/*",
            settings.API_V1_STR + "/admin/*",
        ]

        if user_id:
            # Get user security profile
            security_profile = await self.engine.find_one(
                UserSecurityProfile,
                UserSecurityProfile.user_id == user_id
            )

            if security_profile:
                # Check if this is a known fingerprint
                known_fingerprint = False
                for fp in security_profile.known_fingerprints:
                    if fp.ip == client_ip and fp.user_agent == user_agent:
                        known_fingerprint = True
                        break

                # If this is an unknown fingerprint, check how many different fingerprints
                # have been used recently
                if not known_fingerprint:
                    # Get recent activities for this user
                    recent_time = datetime.utcnow() - timedelta(hours=24)
                    activities = await self.engine.find(
                        UserActivity,
                        (UserActivity.user_id == user_id) & 
                        (UserActivity.timestamp > recent_time)
                    )

                    # Count unique IP addresses
                    unique_ips = set()
                    for activity in activities:
                        unique_ips.add(activity.client_ip)

                    # If too many unique IPs, mark as suspicious
                    if len(unique_ips) > settings.SECURITY_MAX_UNIQUE_IPS_PER_DAY:
                        # Update security profile
                        security_profile.suspicious_activity_count += 1
                        security_profile.last_suspicious_activity = datetime.utcnow()
                        await self.engine.save(security_profile)
                        await self.create_suspicious_activity_log(
                            clickhouse_db=clickhouse_db,
                            user_id=user_id,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            path=path,
                            method=method,
                            status_code=status_code,
                            reason="Too many different IPs used in a short time",
                        )
                        result = True

            for sensitive_path in sensitive_paths:
                if (sensitive_path[:-1] == '*' and path.startswith(sensitive_path[:-1])) or path == sensitive_path:                
                    # Log suspicious activity - now using ClickHouse
                    await self.create_suspicious_activity_log(
                        clickhouse_db=clickhouse_db,
                        user_id=user_id,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        path=path,
                        method=method,
                        status_code=status_code,
                        reason=f"New device accessed sensitive endpoint: {sensitive_path}",
                    )
                    result = True
                    break

        # Check for failed login attempts
        if status_code >= 400:
            for sensitive_path in sensitive_paths:
                if (sensitive_path[:-1] == '*' and path.startswith(sensitive_path[:-1])) or path == sensitive_path:
                    await self.create_suspicious_activity_log(
                        clickhouse_db=clickhouse_db,
                        user_id=user_id,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        path=path,
                        method=method,
                        status_code=status_code,
                        reason="Failed access attempt to sensitive endpoint",
                    )
                    result = True
                    break

        return result

    async def create_suspicious_activity_log(
        self,
        clickhouse_db: AsyncClient,
        *,
        user_id: Optional[str],
        client_ip: str,
        user_agent: str,
        reason: str,
        path: str,
        method: str,
        status_code: int
    ) -> None:
        """
        Log a suspicious activity event in ClickHouse
        
        Args:
            clickhouse_db: ClickHouse database connection
            user_id: The user ID associated with the activity
            client_ip: The IP address that performed the action
            user_agent: The user agent of the request
            reason: The reason why this activity is suspicious
        """
        try:
            # Create the suspicious activity log entry
            now = datetime.utcnow()
            date = now.replace(hour=0, minute=0, second=0, microsecond=0)

            if not user_id:
                user_id = f"{client_ip}#{user_agent}"

            # Determine severity based on reason keywords
            severity = "medium"  # Default
            high_severity_keywords = ["password", "auth", "login", "token", "multiple", "admin"]
            low_severity_keywords = ["new device", "different location", "unusual time"]

            # Check for high severity keywords
            if any(keyword in reason.lower() for keyword in high_severity_keywords):
                severity = "high"
            # Check for low severity keywords
            elif any(keyword in reason.lower() for keyword in low_severity_keywords):
                severity = "low"

            data = {
                "timestamp": now,
                "date": date,
                "user_id": user_id,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "path": path,
                "method": method,
                "status_code": status_code,
                "activity_type": "suspicious_behavior",
                "severity": severity,
                "details": reason,
                "is_resolved": False,
                "resolution_id": None,
            }
            # Insert directly into ClickHouse
            await clickhouse_db.insert(
                SuspiciousActivity.get_table_name(),
                [list(data.values())],
                column_names=list(data.keys())
            )

            # Add structured logging for monitoring
            logger.warning(
                f"Suspicious activity detected",
                extra={
                    "user_id": user_id,
                    "client_ip": client_ip, 
                    "reason": reason,
                    "severity": severity,
                    "timestamp": now.isoformat()
                }
            )

        except Exception as e:
            logger.error(f"Failed to log suspicious activity: {str(e)}")

    async def get_user_activities(
        self,
        db: AsyncClient,
        *,
        user_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> Tuple[List[UserActivity], int]:
        """Get recent activities for a user"""
        try:
            # For count query, use proper parameter syntax with type
            count = await db.query(
                f"SELECT count() FROM {UserActivity.get_table_name()} WHERE user_id = {user_id:String}",
                parameters={"user_id": user_id}
            )

            # Convert generator to list before accessing index
            count_results = list(count.named_results())
            total = count_results[0]["count()"] if count_results else 0

            # For main query, use proper parameter syntax with types
            table_name = UserActivity.get_table_name()
            activities = await db.query(
                f"""
                SELECT *
                FROM {table_name}
                WHERE user_id = {{user_id:String}}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{skip:UInt32}}
                """,
                parameters={
                    "user_id": user_id,
                    "limit": limit,
                    "skip": skip
                },
            )

            # activities.named_results() is also a generator, so use list() here too
            return [UserActivity(**activity) for activity in list(activities.named_results())], total
        except Exception as e:
            logger.error(f"Error getting user activities: {str(e)}")
            return [], 0

    async def get_user_activity_summary(
        self, db: AsyncClient, *, user_id: str, days: int = 7
    ) -> List[UserActivitySummary]:
        """
        Get summary of user activity over the specified period

        Args:
            db: ClickHouse connection
            user_id: User ID
            days: Number of days to analyze

        Returns:
            Dict with activity summary
        """
        try:
            result = await db.query(
                """
                SELECT 
                    toDate(timestamp) AS day,
                    count() AS request_count,
                    avg(process_time) AS avg_response_time,
                    uniq(path) AS unique_endpoints,
                    countIf(status_code >= 400) AS error_count
                FROM {table}
                WHERE user_id = {user_id} AND date >= today() - {days}
                GROUP BY day
                ORDER BY day DESC
                """,
                parameters={
                    "table": UserActivity.get_table_name(),
                    "user_id": user_id,
                    "days": days,
                },
            )

            # Rest of the method remains the same...
            rows = list(result.named_results())

            return [UserActivitySummary(**summary) for summary in rows]
        except Exception as e:
            logger.error(f"Error getting user activity summary: {str(e)}")
            return []

    async def get_security_profile(
        self, 
        db: AgnosticDatabase, 
        *, 
        user_id: str
    ) -> Optional[UserSecurityProfile]:
        """Get or create user security profile"""
        profile = await db.user_security_profiles.find_one({"user_id": user_id})

        if not profile:
            # Create a new profile
            profile = UserSecurityProfile(user_id=user_id).model_dump()
            await db.user_security_profiles.insert_one(profile)
            return UserSecurityProfile(**profile)

        return UserSecurityProfile(**profile)

    async def add_trusted_device(
        self,
        db: AgnosticDatabase,
        *,
        user_id: str,
        device: TrustedDeviceCreate
    ) -> Dict[str, Any]:
        """Add a trusted device to user's security profile"""
        # First get profile
        profile = await self.get_security_profile(db, user_id=user_id)
        if not profile:
            return {}

        # Create new fingerprint
        new_fingerprint = ClientFingerprint(
            ip=device.ip,
            user_agent=device.user_agent,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            request_count=1
        )

        # Add device ID
        fingerprint_dict = new_fingerprint.model_dump()
        fingerprint_dict["id"] = str(ObjectId())  # Generate a new ID
        fingerprint_dict["device_name"] = device.device_name

        # Update profile
        await db.user_security_profiles.update_one(
            {"user_id": user_id},
            {"$push": {"known_fingerprints": fingerprint_dict}}
        )

        return fingerprint_dict

    async def remove_trusted_device(
        self,
        db: AgnosticDatabase,
        *,
        user_id: str,
        device_id: str
    ) -> bool:
        """Remove a trusted device from user's security profile"""
        result = await db.user_security_profiles.update_one(
            {"user_id": user_id},
            {"$pull": {"known_fingerprints": {"id": device_id}}}
        )

        return result.modified_count > 0

    async def get_suspicious_activities(
        self,
        clickhouse_db: AsyncClient,
        *,
        user_id: str,
        skip: int = 0,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get suspicious activities for a specific user from ClickHouse"""
        try:
            result = await clickhouse_db.query(
                """
                SELECT
                    timestamp,
                    user_id,
                    client_ip,
                    user_agent,
                    activity_type,
                    severity,
                    details,
                    is_resolved,
                    resolution_id
                FROM suspicious_activity_logs
                WHERE user_id = {user_id}
                ORDER BY timestamp DESC
                LIMIT {limit} OFFSET {skip}
                """,
                parameters={
                    "user_id": user_id,
                    "limit": limit,
                    "skip": skip
                }
            )

            # Process the results
            activities = list(result.named_results())

            # Generate unique IDs for each record (ClickHouse doesn't have them)
            for activity in activities:
                # Create a deterministic ID from the data
                id_str = f"{activity['user_id']}:{activity['timestamp']}:{activity['client_ip']}"
                activity["id"] = str(hashlib.md5(id_str.encode()).hexdigest())

            return activities
        except Exception as e:
            logger.error(f"Error getting suspicious activities from ClickHouse: {str(e)}")
            return []

    async def get_all_suspicious_activities(
        self,
        clickhouse_db: AsyncClient,
        *,
        skip: int = 0,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get all suspicious activities (admin only) from ClickHouse"""
        try:
            result = await clickhouse_db.query(
                """
                SELECT
                    timestamp,
                    user_id,
                    client_ip,
                    user_agent,
                    activity_type,
                    severity,
                    details,
                    is_resolved,
                    resolution_id
                FROM suspicious_activity_logs
                ORDER BY timestamp DESC
                LIMIT {limit} OFFSET {skip}
                """,
                parameters={
                    "limit": limit,
                    "skip": skip
                }
            )

            # Process the results
            activities = list(result.named_results())

            # Generate unique IDs for each record
            for activity in activities:
                id_str = f"{activity['user_id']}:{activity['timestamp']}:{activity['client_ip']}"
                activity["id"] = str(hashlib.md5(id_str.encode()).hexdigest())

            return activities
        except Exception as e:
            logger.error(f"Error getting all suspicious activities from ClickHouse: {str(e)}")
            return []

    async def record_suspicious_activity(
        self,
        db: AgnosticDatabase,
        *,
        user_id: str,
        client_ip: str,
        user_agent: str,
        activity_type: str,
        severity: str = "medium",
        details: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record a suspicious activity and update user's security profile"""
        # Create suspicious activity record
        now = datetime.utcnow()
        activity = SuspiciousActivity(
            user_id=user_id,
            timestamp=now,
            client_ip=client_ip,
            user_agent=user_agent,
            activity_type=activity_type,
            severity=severity,
            details=details
        ).model_dump()

        result = await db.user_suspicious_activities.insert_one(activity)
        activity["id"] = str(result.inserted_id)

        # Update user's security profile
        await db.user_security_profiles.update_one(
            {"user_id": user_id},
            {
                "$inc": {"suspicious_activity_count": 1},
                "$set": {"last_suspicious_activity": now}
            },
            upsert=True
        )

        return activity

    async def block_ip(
        self,
        db: AgnosticDatabase,
        *,
        ip_address: str,
        reason: str = "Suspicious activity",
        created_by: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Add an IP to the blacklist"""
        ip_block = IPBlacklist(
            ip=ip_address,
            reason=reason,
            created_at=datetime.utcnow(),
            created_by=created_by,
            expires_at=expires_at
        ).model_dump()

        # Use upsert to avoid duplicates
        await db.ip_blacklist.update_one(
            {"ip": ip_address},
            {"$set": ip_block},
            upsert=True
        )

        return ip_block

    async def restrict_user(
        self,
        db: AgnosticDatabase,
        *,
        user_id: str,
        reason: str = "Suspicious activity detected"
    ) -> bool:
        """Restrict a user due to suspicious activity"""
        result = await db.user_security_profiles.update_one(
            {"user_id": user_id},
            {"$set": {"is_restricted": True}}
        )

        # Also log this as a high severity event
        await self.record_suspicious_activity(
            db=db,
            user_id=user_id,
            client_ip="system",
            user_agent="system",
            activity_type="account_restricted",
            severity="high",
            details=reason
        )

        return result.modified_count > 0

    async def get_suspicious_activity_analytics(
        self,
        clickhouse_db: AsyncClient,
        *,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get analytics on suspicious activities from ClickHouse"""
        try:
            # Get overall stats
            summary_result = await clickhouse_db.query(
                """
                SELECT 
                    count() AS total_activities,
                    countIf(severity = 'high') AS high_severity_count,
                    countIf(severity = 'medium') AS medium_severity_count,
                    countIf(severity = 'low') AS low_severity_count,
                    uniq(user_id) AS affected_users,
                    uniq(client_ip) AS unique_ips
                FROM suspicious_activity_logs
                WHERE date >= today() - {days}
                """,
                parameters={"days": days}
            )

            summary = summary_result.first_row_as_dict()

            # Get activity trend by day
            trend_result = await clickhouse_db.query(
                """
                SELECT 
                    date,
                    count() AS activities,
                    countIf(severity = 'high') AS high_severity
                FROM suspicious_activity_logs  
                WHERE date >= today() - {days}
                GROUP BY date
                ORDER BY date
                """,
                parameters={"days": days}
            )

            trend = list(trend_result.named_results())

            # Most common activity types
            types_result = await clickhouse_db.query(
                """
                SELECT 
                    activity_type,
                    count() AS count
                FROM suspicious_activity_logs
                WHERE date >= today() - {days}
                GROUP BY activity_type
                ORDER BY count DESC
                """,
                parameters={"days": days}
            )

            types = list(types_result.named_results())

            # Top users with suspicious activities
            users_result = await clickhouse_db.query(
                """
                SELECT 
                    user_id,
                    count() AS activity_count,
                    max(timestamp) AS latest_activity
                FROM suspicious_activity_logs
                WHERE date >= today() - {days}
                GROUP BY user_id
                ORDER BY activity_count DESC
                LIMIT 10
                """,
                parameters={"days": days}
            )

            users = list(users_result.named_results())

            return {
                "summary": summary,
                "trend": trend,
                "activity_types": types,
                "top_users": users,
                "days_analyzed": days
            }
        except Exception as e:
            logger.error(f"Error getting suspicious activity analytics: {str(e)}")
            return {
                "summary": {},
                "trend": [],
                "activity_types": [],
                "top_users": [],
                "days_analyzed": days,
                "error": str(e)
            }


# Create a singleton instance
user_activity = CRUDUserActivity(UserActivity)
