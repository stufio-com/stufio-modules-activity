from __future__ import annotations
from typing import Optional
from datetime import datetime
from pydantic import ConfigDict, Field
from odmantic import Field as MongoField
from stufio.db.mongo_base import MongoBase, datetime_now_sec
from stufio.db.clickhouse_base import ClickhouseBase

class SuspiciousActivity(ClickhouseBase):
    """Model for storing suspicious user activities in ClickHouse"""
    timestamp: datetime = Field(default_factory=datetime_now_sec)
    date: datetime = Field(
        default_factory=lambda: datetime_now_sec().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    )
    user_id: str
    client_ip: str
    user_agent: str
    path: str  # API path where suspicious activity occurred
    method: str  # HTTP method used
    status_code: int  # Response status code
    activity_type: str  # login_attempt, password_change, etc.
    severity: str  # low, medium, high
    details: Optional[str] = None
    is_resolved: bool = False
    resolution_id: Optional[str] = None  # Reference to resolution record if needed

    model_config = ConfigDict(table_name="user_suspicious_activity")


class IPBlacklist(MongoBase):
    """Model for storing blocked IP addresses"""
    ip: str = MongoField(index=True)
    reason: str
    created_at: datetime = MongoField(default_factory=datetime_now_sec)
    created_by: Optional[str] = None
    expires_at: Optional[datetime] = None

    model_config = ConfigDict(collection="user_ip_blacklist")
