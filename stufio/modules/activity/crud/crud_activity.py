from datetime import datetime, timedelta, timezone
import hashlib
import logging
from typing import List, Optional, Dict, Any, Tuple
from odmantic import ObjectId
import uuid

from stufio.core.config import get_settings
from stufio.crud.mongo_base import CRUDMongo
from stufio.crud.clickhouse_base import CRUDClickhouse
from stufio.db.clickhouse_base import datetime_now_sec
from ..models import (
    IPBlacklist, UserActivity, UserSecurityProfile, 
    ClientFingerprint, SuspiciousActivity
)
from ..schemas import TrustedDeviceCreate, UserActivitySummary

settings = get_settings()
logger = logging.getLogger(__name__)

class CRUDUserActivity:
    """CRUD for UserActivity with both MongoDB and ClickHouse support"""

    def __init__(self):
        """Initialize both MongoDB and ClickHouse handlers"""
        self.security_profiles = CRUDMongo(UserSecurityProfile)
        self.ip_blacklist = CRUDMongo(IPBlacklist)
        self.activity = CRUDClickhouse(UserActivity)
        self.suspicious = CRUDClickhouse(SuspiciousActivity)

    async def create_activity(
        self,
        *,
        user_id: Optional[str],
        path: str,
        method: str,
        client_ip: str,
        user_agent: str,
        status_code: int,
        process_time: float,
    ) -> bool:
        """Record an API request in ClickHouse for analytics"""
        try:
            is_authenticated = bool(user_id)
            effective_user_id = user_id if user_id else f"anon-{client_ip}"

            # Generate a unique ID for this activity
            event_id = str(uuid.uuid4())
            current_time = datetime_now_sec()

            # Create the activity record with explicit timestamp and ID
            api_request = UserActivity(
                event_id=event_id,  # Set explicit ID
                timestamp=current_time,  # Set explicit timestamp
                date=current_time.replace(hour=0, minute=0, second=0, microsecond=0),
                user_id=effective_user_id,
                path=path,
                method=method,
                client_ip=client_ip,
                user_agent=user_agent,
                status_code=status_code,
                process_time=process_time,
                is_authenticated=is_authenticated,
            )

            # Use the dict_for_insert method to ensure proper data formatting
            insert_data = api_request.dict_for_insert()

            # Get the ClickHouse client directly for more control
            client = await self.activity.client

            # Extract column names and values for explicit insertion
            columns = list(insert_data.keys())
            values = [list(insert_data.values())]

            # Insert using explicit column names
            await client.insert(
                UserActivity.get_table_name(),
                values,
                column_names=columns  # Explicitly specify column names
            )

            # Update user security profile if this is an authenticated user
            if is_authenticated:
                await self._update_user_security_profile(effective_user_id, client_ip, user_agent)

            return True
        except Exception as e:
            logger.error(f"Error recording API request in ClickHouse: {str(e)}", exc_info=True)

            # Add diagnostics to help debug the issue
            try:
                if 'insert_data' in locals():
                    logger.debug(f"Insert data: {insert_data}")

                # Get actual table structure
                schema_result = await client.query(f"DESCRIBE TABLE {UserActivity.get_table_name()}")
                schema_columns = [row[0] for row in schema_result.result_rows]
                logger.debug(f"ClickHouse table columns: {schema_columns}")

                if 'insert_data' in locals():
                    logger.debug(f"Data columns: {list(insert_data.keys())}")

                    # Show differences
                    table_set = set(schema_columns)
                    data_set = set(insert_data.keys())
                    missing_in_data = table_set - data_set
                    extra_in_data = data_set - table_set

                    if missing_in_data:
                        logger.error(f"Columns in table but missing in data: {missing_in_data}")
                    if extra_in_data:
                        logger.error(f"Columns in data but missing in table: {extra_in_data}")
            except Exception as debug_e:
                logger.error(f"Error during diagnostics: {debug_e}")

            return False

    async def _update_user_security_profile(
        self,
        user_id: str,
        client_ip: str,
        user_agent: str
    ) -> None:
        """Update the user's security profile with this client info"""
        # Get or create security profile
        security_profile = await self.security_profiles.get_by_field("user_id", user_id)

        if not security_profile:
            # Create new profile
            security_profile = UserSecurityProfile(
                user_id=user_id,
                known_fingerprints=[
                    ClientFingerprint(
                        ip=client_ip,
                        user_agent=user_agent
                    )
                ]
            )
            await self.security_profiles.create(security_profile)
            return

        # Check if this fingerprint exists
        fingerprint_exists = False
        for fp in security_profile.known_fingerprints:
            if fp.ip == client_ip and fp.user_agent == user_agent:
                # Update existing fingerprint
                fp.last_seen = datetime.now(timezone.utc)
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

        # Update the profile - EXCLUDE ID FIELD
        update_data = security_profile.model_dump(exclude={"id"})
        try:
            await self.security_profiles.update(security_profile, update_data)
        except Exception as e:
            logger.error(f"Error updating security profile: {e}", exc_info=True)

    async def check_suspicious_activity(
        self,
        *,
        user_id: Optional[str],
        client_ip: str,
        user_agent: str,
        path: str,
        method: str,
        status_code: int,
    ) -> bool:
        """Check if this activity appears suspicious"""
        result = False
        sensitive_paths = [
            settings.API_V1_STR + "/login/*",
            settings.API_V1_STR + "/users/*",
            settings.API_V1_STR + settings.API_ADMIN_STR + "/*",
        ]

        if user_id:
            # Get user security profile
            security_profile = await self.security_profiles.get_by_field("user_id", user_id)

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
                    recent_time = datetime.now(timezone.utc) - timedelta(hours=24)

                    # Query ClickHouse directly
                    ch_client = await self.activity.client
                    activities = await ch_client.query(
                        f"""
                        SELECT DISTINCT client_ip
                        FROM {UserActivity.get_table_name()}
                        WHERE user_id = {{user_id:String}}
                        AND timestamp > {{recent_time:DateTime}}
                        """,
                        parameters={
                            "user_id": user_id,
                            "recent_time": recent_time
                        }
                    )

                    # Get unique IPs from result
                    unique_ips = set(row[0] for row in activities.result_rows)

                    # If too many unique IPs, mark as suspicious
                    if len(unique_ips) > settings.activity_SECURITY_MAX_UNIQUE_IPS_PER_DAY:
                        # Update security profile
                        security_profile.suspicious_activity_count += 1
                        security_profile.last_suspicious_activity = datetime.now(timezone.utc)
                        await self.security_profiles.update(
                            security_profile,
                            security_profile.model_dump()
                        )

                        await self.create_suspicious_activity_log(
                            user_id=user_id,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            path=path,
                            method=method,
                            status_code=status_code,
                            reason="Too many different IPs used in a short time",
                        )
                        result = True

            # Check for sensitive path access
            for sensitive_path in sensitive_paths:
                if (sensitive_path.endswith('*') and path.startswith(sensitive_path[:-1])) or path == sensitive_path:                
                    # Log suspicious activity
                    await self.create_suspicious_activity_log(
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
                if (sensitive_path.endswith('*') and path.startswith(sensitive_path[:-1])) or path == sensitive_path:
                    await self.create_suspicious_activity_log(
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
        *,
        user_id: Optional[str],
        client_ip: str,
        user_agent: str,
        reason: str,
        path: str,
        method: str,
        status_code: int
    ) -> None:
        """Log a suspicious activity event in ClickHouse"""
        try:
            # Create the suspicious activity log entry
            now = datetime.now(timezone.utc)
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

            # Create suspicious activity record
            suspicious = SuspiciousActivity(
                timestamp=now,
                date=date,
                user_id=user_id,
                client_ip=client_ip,
                user_agent=user_agent,
                path=path,
                method=method,
                status_code=status_code,
                activity_type="suspicious_behavior",
                severity=severity,
                details=reason,
                is_resolved=False,
                resolution_id=None,
            )

            # Insert into ClickHouse
            await self.suspicious.create(suspicious)

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
            logger.error(f"❌ Failed to log suspicious activity: {str(e)}")

    async def get_user_activities(
        self,
        *,
        user_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> Tuple[List[UserActivity], int]:
        """Get recent activities for a user"""
        try:
            # Use self.activity instead of db
            client = await self.activity.client
            count = await client.query(
                f"SELECT count() FROM {UserActivity.get_table_name()} WHERE user_id = {{user_id:String}}",
                parameters={"user_id": user_id}
            )

            # Convert generator to list before accessing index
            count_results = list(count.named_results())
            total = count_results[0]["count()"] if count_results else 0

            # Use self.activity for the main query
            table_name = UserActivity.get_table_name()
            activities = await client.query(
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

            return [UserActivity(**activity) for activity in list(activities.named_results())], total
        except Exception as e:
            logger.error(f"Error getting user activities: {str(e)}")
            return [], 0

    async def get_user_activity_summary(
        self, *, user_id: str, days: int = 7
    ) -> List[UserActivitySummary]:
        """Get summary of user activity over the specified period"""
        try:
            # Use self.activity instead of self.clickhouse
            client = await self.activity.client
            result = await client.query(
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

            rows = list(result.named_results())
            return [UserActivitySummary(**summary) for summary in rows]
        except Exception as e:
            logger.error(f"Error getting user activity summary: {str(e)}")
            return []

    async def get_security_profile(
        self,
        user_id: str
    ) -> Optional[UserSecurityProfile]:
        """Get or create user security profile"""
        # Use self.security_profiles instead of self.mongo
        profile = await self.security_profiles.get_by_field("user_id", user_id)

        if not profile:
            # Create a new profile
            profile = UserSecurityProfile(user_id=user_id)
            return await self.security_profiles.create(profile)

        return profile

    async def add_trusted_device(
        self,
        user_id: str,
        device: TrustedDeviceCreate
    ) -> Dict[str, Any]:
        """Add a trusted device to user's security profile"""
        # First get profile
        profile = await self.get_security_profile(user_id=user_id)
        if not profile:
            return {}

        # Create new fingerprint
        new_fingerprint = ClientFingerprint(
            ip=device.ip,
            user_agent=device.user_agent,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            request_count=1
        )

        # Add device ID
        fingerprint_dict = new_fingerprint.model_dump()
        fingerprint_dict["id"] = str(ObjectId())  # Generate a new ID
        fingerprint_dict["device_name"] = device.device_name

        # Use direct collection update instead of update() method
        collection = await self.security_profiles.engine.get_collection(UserSecurityProfile.get_collection_name())
        await collection.update_one(
            {"user_id": profile.user_id},
            {
                "$push": {"known_fingerprints": fingerprint_dict},
                "$set": {"last_trusted_device": fingerprint_dict}
            },
            upsert=False
        )

        return fingerprint_dict

    async def remove_trusted_device(
        self,
        user_id: str,
        device_id: str
    ) -> bool:
        """Remove a trusted device from user's security profile"""
        # Use self.security_profiles instead of self.mongo
        collection = await self.security_profiles.engine.get_collection(UserSecurityProfile.get_collection_name())
        result = await collection.update_one(
            {"user_id": user_id},
            {"$pull": {"known_fingerprints": {"id": device_id}}}
        )
        if result.modified_count == 0:
            return False
        return True

    async def get_suspicious_activities(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get suspicious activities for a specific user from ClickHouse"""
        try:
            # Use self.suspicious instead of self.clickhouse
            client = await self.suspicious.client
            result = await client.query(
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
                FROM {table}
                WHERE user_id = {user_id}
                ORDER BY timestamp DESC
                LIMIT {limit} OFFSET {skip}
                """,
                parameters={
                    "table": SuspiciousActivity.get_table_name(),
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
        skip: int = 0,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get all suspicious activities (admin only) from ClickHouse"""
        try:
            # Use self.suspicious instead of self.clickhouse
            client = await self.suspicious.client
            result = await client.query(
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
                FROM {table}
                ORDER BY timestamp DESC
                LIMIT {limit} OFFSET {skip}
                """,
                parameters={
                    "table": SuspiciousActivity.get_table_name(),
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
        user_id: str,
        client_ip: str,
        user_agent: str,
        activity_type: str,
        severity: str = "medium",
        details: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record a suspicious activity and update user's security profile"""
        # Create suspicious activity record
        now = datetime.now(timezone.utc)
        activity = SuspiciousActivity(
            user_id=user_id,
            timestamp=now,
            client_ip=client_ip,
            user_agent=user_agent,
            activity_type=activity_type,
            severity=severity,
            details=details
        )

        # Use self.suspicious's insert method
        await self.suspicious.create(activity)
        activity_dict = activity.model_dump()

        # Update user's security profile using self.security_profiles
        collection = await self.security_profiles.engine.get_collection(UserSecurityProfile.get_collection_name())
        await collection.update_one(
            {"user_id": user_id},
            {
                "$inc": {"suspicious_activity_count": 1},
                "$set": {"last_suspicious_activity": now}
            },
            upsert=True
        )

        return activity_dict

    async def block_ip(
        self,
        ip_address: str,
        reason: str = "Suspicious activity",
        created_by: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Add an IP to the blacklist"""
        ip_block = IPBlacklist(
            ip=ip_address,
            reason=reason,
            created_at=datetime.now(timezone.utc),
            created_by=created_by,
            expires_at=expires_at
        )

        # Use self.ip_blacklist create method with upsert logic
        existing = await self.ip_blacklist.get_by_field("ip", ip_address)
        if existing:
            # Update if exists
            for key, value in ip_block.model_dump().items():
                setattr(existing, key, value)
            await self.ip_blacklist.update(existing, existing)
            return existing.model_dump()
        else:
            # Create new
            created = await self.ip_blacklist.create(ip_block)
            return created.model_dump()

    async def unblock_ip(
        self,
        ip_address: str
    ) -> bool:
        """Remove an IP from the blacklist"""
        # Use self.ip_blacklist's get and remove methods
        ip_block = await self.ip_blacklist.get_by_field("ip", ip_address)
        if not ip_block:
            return False

        await self.ip_blacklist.remove(ip_block.id)
        return True

    async def check_ip_blacklisted(
        self, ip_address: str
    ) -> Tuple[bool, Optional[str]]:
        """Check if an IP is blacklisted"""
        # Use self.ip_blacklist instead of db.ip_blacklist
        ip_block = await self.ip_blacklist.get_by_field("ip", ip_address)
        if ip_block:
            return True, ip_block.reason

        return False, None

    async def restrict_user(
        self,
        user_id: str,
        reason: str = "Suspicious activity detected"
    ) -> bool:
        """Restrict a user due to suspicious activity"""
        # Get the user profile first
        profile = await self.security_profiles.get_by_field("user_id", user_id)
        if not profile:
            return False

        # Update using CRUD methods
        profile.is_restricted = True
        await self.security_profiles.update(profile, {"is_restricted": True})

        # Also log this as a high severity event
        await self.record_suspicious_activity(
            user_id=user_id,
            client_ip="system",
            user_agent="system",
            activity_type="account_restricted",
            severity="high",
            details=reason
        )

        return True

    async def get_suspicious_activity_analytics(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get analytics on suspicious activities from ClickHouse"""
        try:
            # Use self.suspicious instead of self.clickhouse
            client = await self.suspicious.client

            # Get overall stats
            summary_result = await client.query(
                """
                SELECT 
                    count() AS total_activities,
                    countIf(severity = 'high') AS high_severity_count,
                    countIf(severity = 'medium') AS medium_severity_count,
                    countIf(severity = 'low') AS low_severity_count,
                    uniq(user_id) AS affected_users,
                    uniq(client_ip) AS unique_ips
                FROM {table}
                WHERE date >= today() - {days}
                """,
                parameters={
                    "table": SuspiciousActivity.get_table_name(),
                    "days": days
                }
            )

            summary = summary_result.first_row_as_dict()

            # Get activity trend by day
            trend_result = await client.query(
                """
                SELECT 
                    date,
                    count() AS activities,
                    countIf(severity = 'high') AS high_severity
                FROM {table} 
                WHERE date >= today() - {days}
                GROUP BY date
                ORDER BY date
                """,
                parameters={
                    "table": SuspiciousActivity.get_table_name(),
                    "days": days
                }
            )

            trend = list(trend_result.named_results())

            # Most common activity types
            types_result = await client.query(
                """
                SELECT 
                    activity_type,
                    count() AS count
                FROM {table}
                WHERE date >= today() - {days}
                GROUP BY activity_type
                ORDER BY count DESC
                """,
                parameters={
                    "table": SuspiciousActivity.get_table_name(),
                    "days": days
                }
            )

            types = list(types_result.named_results())

            # Top users with suspicious activities
            users_result = await client.query(
                """
                SELECT 
                    user_id,
                    count() AS activity_count,
                    max(timestamp) AS latest_activity
                FROM {table}
                WHERE date >= today() - {days}
                GROUP BY user_id
                ORDER BY activity_count DESC
                LIMIT 10
                """,
                parameters={
                    "table": SuspiciousActivity.get_table_name(),
                    "days": days
                }
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
user_activity = CRUDUserActivity()
