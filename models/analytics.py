from datetime import datetime, date
from pydantic import ConfigDict
from stufio.db.clickhouse_base import ClickhouseBase


class UserActivitySummary(ClickhouseBase):
    """Model for user activity summary results"""
    day: date
    request_count: int
    avg_response_time: float
    unique_endpoints: int
    error_count: int

    model_config = ConfigDict(table_name="user_activity_summary")


class UserActivityPathStatistics(ClickhouseBase):
    """Model for API path statistics"""
    day: date
    path: str
    request_count: int
    avg_response_time: float
    max_response_time: float
    error_rate: float
    unique_users: int

    model_config = ConfigDict(table_name="user_activity_path_stat")


class UserActivityErrorStatistics(ClickhouseBase):
    """Model for API error report"""
    day: date
    path: str
    status_code: int
    error_count: int
    latest_occurrence: datetime

    model_config = ConfigDict(table_name="user_activity_error_stat")
