from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List


class TrustedDeviceBase(BaseModel):
    """Base schema for trusted device"""
    device_name: Optional[str] = None
    ip: str
    user_agent: str


class TrustedDeviceCreate(TrustedDeviceBase):
    """Schema for creating a trusted device"""
    pass


class TrustedDeviceResponse(TrustedDeviceBase):
    """Response schema for trusted device"""
    id: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    request_count: int


class SuspiciousActivityBase(BaseModel):
    """Base schema for suspicious activity"""
    timestamp: datetime
    user_id: str
    client_ip: str
    user_agent: str
    path: str
    method: str
    status_code: int
    activity_type: str  # login_attempt, password_change, etc.
    severity: str  # low, medium, high
    details: Optional[str] = None


class SuspiciousActivityCreate(SuspiciousActivityBase):
    """Schema for creating suspicious activity record"""
    pass


class SuspiciousActivityResponse(SuspiciousActivityBase):
    """Response schema for suspicious activity"""
    id: str
    is_resolved: bool = False
    resolution_id: Optional[str] = None


class UserSecurityProfileBase(BaseModel):
    """Base schema for user security profile"""
    user_id: str
    suspicious_activity_count: int = 0
    last_suspicious_activity: Optional[datetime] = None
    is_restricted: bool = False


class UserSecurityProfileResponse(UserSecurityProfileBase):
    """Response schema for user security profile"""
    known_fingerprints: List[TrustedDeviceResponse] = []


class IPBlockRequest(BaseModel):
    """Schema for blocking an IP address"""
    reason: str
    expires_at: Optional[datetime] = None


class UserRestrictionRequest(BaseModel):
    """Schema for restricting a user"""
    reason: str
    restriction_level: str = "full"  # full, partial
    expires_at: Optional[datetime] = None