from datetime import datetime, timedelta
from typing import List, Optional
from odmantic.index import Index
from odmantic import Field as MongoField
from pydantic import Field
from stufio.db.mongo_base import MongoBase, datetime_now_sec, datetime_now
from stufio.db.clickhouse_base import ClickhouseBase


class RateLimitConfig(MongoBase):
    """Rate limit configuration stored in MongoDB"""
    endpoint: str = MongoField(index=True)
    max_requests: int
    window_seconds: int
    active: bool = MongoField(default=True, index=True)
    bypass_roles: List[str] = MongoField(default_factory=list)
    created_at: datetime = MongoField(default_factory=datetime_now_sec)
    updated_at: datetime = MongoField(default_factory=datetime_now_sec)
    description: Optional[str] = None

    model_config = {
        "collection": "rate_limit_configs",
        "indexes": lambda: [
            Index("endpoint", "active", unique=True), 
        ],
    }

class RateLimitOverride(MongoBase):
    """
    Rate limit override for specific users
    Stored in MongoDB collection 'rate_limit_overrides'
    """
    user_id: str = MongoField(index=True)
    path: str = MongoField(default="*", index=True)  # * means all paths
    max_requests: int
    window_seconds: int
    created_at: datetime = MongoField(default_factory=datetime_now_sec)
    expires_at: Optional[datetime] = None
    created_by: Optional[str] = None
    reason: Optional[str] = None

    model_config = {
        "collection": "rate_limit_overrides",
        "indexes": lambda: [
            Index("user_id", "path", unique=True),
        ],
    }


class RateLimitViolation(ClickhouseBase):
    """Rate limit violations for analytics in ClickHouse"""
    timestamp: datetime = Field(default_factory=datetime_now_sec)
    date: datetime = Field(default_factory=lambda: datetime_now())
    key: str  # The rate limit key that was violated
    type: str  # ip, user, endpoint
    limit: int  # The max requests allowed
    attempts: int  # How many attempts were made
    user_id: Optional[str] = None
    client_ip: Optional[str] = None
    endpoint: Optional[str] = None

    model_config = {"table_name": "rate_limit_violations"}


class RateLimit(ClickhouseBase):
    """Rate limiting counter document in ClickHouse"""
    timestamp: datetime = Field(default_factory=datetime_now_sec)
    date: datetime = Field(default_factory=lambda: datetime_now())
    key: str  # Can be user_id, ip, or endpoint+ip
    type: str  # 'ip', 'user', 'endpoint'
    counter: int = Field(default=1)
    window_start: datetime = Field(default_factory=datetime_now_sec)
    window_end: datetime = Field(default_factory=lambda: datetime_now_sec() + timedelta(seconds=60))
    ip: Optional[str] = None
    user_id: Optional[str] = None
    endpoint: Optional[str] = None

    model_config = {"table_name": "rate_limits"}


class UserRateLimit(MongoBase):
    """User rate limit status stored in MongoDB"""
    user_id: str = MongoField(index=True, unique=True)
    is_limited: bool = MongoField(default=False, index=True)
    reason: Optional[str] = None
    limited_until: Optional[datetime] = MongoField(default=None, index=True)
    created_at: datetime = MongoField(default_factory=datetime_now_sec)
    updated_at: datetime = MongoField(default_factory=datetime_now_sec)

    model_config = {
        "collection": "user_rate_limits"
    }
