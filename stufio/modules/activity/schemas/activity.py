from pydantic import BaseModel, Field
from datetime import datetime, date
from typing import Optional

from stufio.modules.events.schemas.base import BaseEventPayload


class UserActivityResponse(BaseModel):
    """Response model for user activity"""
    timestamp: datetime
    date: date
    user_id: Optional[str] = None
    path: str
    method: str
    client_ip: str
    user_agent: str
    status_code: int
    process_time: float  # In seconds
    is_authenticated: bool = False


class UserActivityFilter(BaseModel):
    """Filter model for querying user activity"""
    user_id: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    client_ip: Optional[str] = None
    status_code: Optional[int] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    is_authenticated: Optional[bool] = None


class UserActivitySummary(BaseModel):
    """Summary statistics of user activity"""
    total_requests: int
    average_response_time: float
    error_rate: float
    unique_paths: int
    top_paths: list[dict[str, str | int | float]]
    last_activity: Optional[datetime] = None


