from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class RateLimitStatus(BaseModel):
    total_allowed: int
    remaining: int
    reset_at: datetime
    window_seconds: int

class EndpointRateLimitConfig(BaseModel):
    max_requests: int
    window_seconds: int

class RateLimitOverride(BaseModel):
    id: Optional[str] = None
    user_id: str
    path: str = "*"  # * means all paths
    max_requests: int
    window_seconds: int
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

class RateLimitConfigBase(BaseModel):
    """Base schema for rate limit configuration"""
    endpoint: str
    max_requests: int
    window_seconds: int
    bypass_roles: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    active: bool = True

class RateLimitConfigCreate(RateLimitConfigBase):
    """Schema for creating a rate limit configuration"""
    pass

class RateLimitConfigUpdate(BaseModel):
    """Schema for updating a rate limit configuration"""
    max_requests: Optional[int] = None
    window_seconds: Optional[int] = None
    bypass_roles: Optional[List[str]] = None
    description: Optional[str] = None
    active: Optional[bool] = None

class RateLimitConfigResponse(RateLimitConfigBase):
    """Response schema for rate limit configuration"""
    id: str
    created_at: datetime
    updated_at: datetime