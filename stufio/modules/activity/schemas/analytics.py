from pydantic import BaseModel, Field
from typing import Annotated, List, Dict, Any, Optional
from datetime import datetime


class PathStatistics(BaseModel):
    """Statistics for a specific API path"""

    path: str
    request_count: int
    avg_response_time: float
    max_response_time: float
    error_rate: float = Field(0.0, ge=0, le=1)
    unique_users: int


class ErrorReport(BaseModel):
    """Information about an API error"""

    path: str
    status_code: int
    error_count: int
    latest_occurrence: datetime


class UserActivityMetrics(BaseModel):
    """Metrics about user activity"""

    user_id: Optional[str] = None
    total_requests: int
    avg_requests_per_day: float
    error_rate: Annotated[float, Field(strict=True, gt=0, le=1)] = 0.0
    most_used_endpoint: str
    last_activity: Optional[datetime] = None



class PerformanceMetrics(BaseModel):
    """API performance metrics"""

    path: str
    avg_response_time: float
    p50_response_time: float
    p95_response_time: float
    p99_response_time: float
    requests_per_minute: float
    error_rate: Annotated[float, Field(strict=True, gt=0, le=1)] = 0.0
    timeframe: str  # e.g., "last_hour", "last_day", "last_week"



class ApiUsageSummary(BaseModel):
    """Summary of overall API usage"""

    total_requests: int
    unique_users: int
    unique_paths: int
    avg_response_time: float
    error_rate: Annotated[float, Field(strict=True, gt=0, le=1)] = 0.0
    timeframe: str  # e.g., "last_hour", "last_day", "last_week"
    most_used_endpoints: List[Dict[str, Any]]  # Top endpoints by usage
    timestamp: datetime  # When this report was generated


class ViolationReport(BaseModel):
    """Information about a rate limit violation"""

    timestamp: datetime
    key: str
    type: str
    limit: int
    attempts: int
    user_id: Optional[str] = None
    client_ip: Optional[str] = None
    endpoint: Optional[str] = None


class ViolationSummary(BaseModel):
    """Summary statistics about rate limit violations"""

    total_violations: int
    unique_ips: int
    unique_users: int
    unique_endpoints: int
    avg_attempts: float


class ViolationsByType(BaseModel):
    """Rate limit violations grouped by type"""

    type: str
    count: int


class TopViolator(BaseModel):
    """Information about a top rate limit violator"""

    client_ip: str
    violations: int


class ViolationsByDay(BaseModel):
    """Rate limit violations grouped by day"""

    date: datetime
    violations: int


class ViolationAnalytics(BaseModel):
    """Complete analytics for rate limit violations"""

    summary: ViolationSummary
    by_type: List[ViolationsByType]
    top_ips: List[TopViolator]
    by_day: List[ViolationsByDay]
    days_analyzed: int = 7
