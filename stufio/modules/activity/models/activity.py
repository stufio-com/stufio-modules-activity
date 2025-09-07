from __future__ import annotations
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta
import uuid
from odmantic import Field as MongoField
from odmantic import EmbeddedModel
from pydantic import Field as PydanticField
from stufio.db.clickhouse_base import ClickhouseBase, datetime_now_sec, datetime_now
from stufio.db.mongo_base import MongoBase

class ClientFingerprint(EmbeddedModel):
    """Client metadata for fingerprinting"""
    # Remove duplicate 'ip' field
    ip: str
    device_name: Optional[str] = None
    user_agent: str
    first_seen: datetime = MongoField(default_factory=datetime_now_sec)
    last_seen: datetime = MongoField(default_factory=datetime_now_sec)
    request_count: int = MongoField(default=1)


class UserActivity(ClickhouseBase):
    """ClickHouse schema for user request activity"""
    # Define a UUID field for unique identification
    event_id: str = PydanticField(default_factory=lambda: str(uuid.uuid4()))

    # Timestamp fields - make sure they're properly set only once
    timestamp: datetime = PydanticField(default_factory=datetime_now_sec)
    date: datetime = PydanticField(default_factory=lambda: datetime_now())
    user_id: str = PydanticField(default="")
    path: str
    method: str
    client_ip: str
    user_agent: str
    status_code: int
    process_time: float  # In seconds
    is_authenticated: bool = PydanticField(default=False)

    model_config = {
        "table_name": "user_activity", 
        "clickhouse_settings": {
            "primary_key": "event_id",  # Set explicit primary key
            "order_by": "(timestamp, event_id)"  # Define ordering
        }
    }

    def dict_for_insert(self) -> Dict[str, Any]:
        """Convert model to a dict suitable for ClickHouse insert"""
        data = self.model_dump(exclude_unset=False, exclude_none=True)

        # Ensure timestamp and date are set properly
        if "timestamp" not in data or data["timestamp"] is None:
            data["timestamp"] = datetime_now_sec()

        if "date" not in data or data["date"] is None:
            data["date"] = data["timestamp"].replace(
                hour=0, minute=0, second=0, microsecond=0
            )

        # Generate a UUID for event_id if not present
        if "event_id" not in data or not data["event_id"]:
            data["event_id"] = str(uuid.uuid4())

        # Ensure user_id is never None
        if data.get("user_id") is None:
            data["user_id"] = f"anon-{data.get('client_ip', 'unknown')}"

        return data


class RateLimit(ClickhouseBase):
    """Rate limiting counter document"""
    # Use PydanticField for ClickHouse models
    key: str  # Can be user_id, ip, or endpoint+ip
    counter: int = PydanticField(default=1)
    window_start: datetime = PydanticField(default_factory=datetime_now_sec)
    window_end: datetime = PydanticField(default_factory=lambda: datetime_now_sec() + timedelta(seconds=60))

    # Use model_config for table name
    model_config = {"table_name": "rate_limits"}


class RateLimitOverride(MongoBase):
    """Rate limit override document"""
    # Use MongoField for MongoDB models
    user_id: str = MongoField(default=None)
    path: str = MongoField()  # Add MongoField here
    reason: str = MongoField()  # Add MongoField here
    expires_at: datetime = MongoField(default_factory=lambda: datetime_now_sec() + timedelta(days=1))

    # Use model_config for collection name
    model_config = {"collection": "rate_limit_overrides"}


class UserSecurityProfile(MongoBase):
    """User security profile with known devices and suspicious activity flags"""
    user_id: str = MongoField(index=True)
    known_fingerprints: List[ClientFingerprint] = MongoField(default_factory=list)
    suspicious_activity_count: int = MongoField(default=0)
    last_suspicious_activity: Optional[datetime] = MongoField(default=None)  # Add MongoField
    is_restricted: bool = MongoField(default=False)
    last_trusted_device: Optional[Dict[str, Any]] = MongoField(default=None)

    # Use model_config for collection name
    model_config = {"collection": "user_security_profiles"}
