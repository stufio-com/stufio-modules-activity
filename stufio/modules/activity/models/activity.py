from __future__ import annotations
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta
from odmantic import Field as MongoField
from odmantic import Index, EmbeddedModel
from pydantic import ConfigDict, Field
from stufio.db.clickhouse_base import ClickhouseBase, datetime_now_sec
from stufio.db.mongo_base import MongoBase

class ClientFingerprint(EmbeddedModel):
    """Client metadata for fingerprinting"""
    ip: str
    device_name: Optional[str] = None
    ip: str
    user_agent: str
    first_seen: datetime = MongoField(default_factory=datetime_now_sec)
    last_seen: datetime = MongoField(default_factory=datetime_now_sec)
    request_count: int = MongoField(default=1)


class UserActivity(ClickhouseBase):
    """ClickHouse schema for user request activity"""

    timestamp: datetime = Field(default_factory=datetime_now_sec)
    date: datetime = Field(
        default_factory=lambda: datetime_now_sec().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    )
    user_id: str = Field(default=None)
    path: str
    method: str
    client_ip: str
    user_agent: str
    status_code: int
    process_time: float  # In seconds
    is_authenticated: bool = Field(default=False)

    model_config = ConfigDict(table_name="user_activity")

    def dict_for_insert(self) -> Dict[str, Any]:
        """Convert model to a dict suitable for ClickHouse insert"""
        data = self.model_dump(exclude_unset=False, exclude_none=True)

        # Ensure timestamp and date are set
        if "timestamp" not in data or data["timestamp"] is None:
            data["timestamp"] = datetime_now_sec()

        if "date" not in data or data["date"] is None:
            data["date"] = data["timestamp"].replace(
                hour=0, minute=0, second=0, microsecond=0
            )

        return data


class RateLimit(ClickhouseBase):
    """Rate limiting counter document"""
    key: str = Field(index=True)  # Can be user_id, ip, or endpoint+ip
    counter: int = Field(default=1)
    window_start: datetime = Field(default_factory=datetime_now_sec)
    window_end: datetime = Field(default_factory=lambda: datetime_now_sec() + timedelta(seconds=60))

    # Use model_config instead of nested Config class
    model_config = ConfigDict(
        collection="rate_limits"
    )


class UserSecurityProfile(MongoBase):
    """User security profile with known devices and suspicious activity flags"""
    user_id: str = MongoField(index=True)
    known_fingerprints: List[ClientFingerprint] = MongoField(default_factory=list)
    suspicious_activity_count: int = MongoField(default=0)
    last_suspicious_activity: Optional[datetime] = None
    is_restricted: bool = MongoField(default=False)

    # Use model_config instead of nested Config class
    model_config = ConfigDict(
        collection="user_security_profiles"
    )
