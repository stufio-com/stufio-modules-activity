from ast import Dict
from typing import Any, List
from clickhouse_connect.driver.asyncclient import AsyncClient
from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.params import Query
from motor.core import AgnosticDatabase

from stufio import models
from stufio.api import deps
from stufio.schemas import Msg
from ..schemas import (
    SuspiciousActivityResponse,
)
from ..crud.crud_activity import user_activity

router = APIRouter()


# Admin endpoints
@router.post("/security/block-ip/{ip_address}", response_model=Msg)
async def admin_block_ip(
    ip_address: str,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> Msg:
    """
    Admin endpoint to block an IP address.
    """
    await user_activity.block_ip(ip_address=ip_address)
    return Msg(msg=f"IP {ip_address} has been blocked")


@router.post("/security/restrict-user/{user_id}", response_model=Msg)
async def admin_restrict_user(
    user_id: str,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> Msg:
    """
    Admin endpoint to restrict a user due to suspicious activity.
    """
    await user_activity.restrict_user(user_id=user_id)
    return Msg(msg=f"User {user_id} has been restricted")


# For admin endpoints:
@router.get(
    "/security/suspicious-activities",
    response_model=List[SuspiciousActivityResponse],
)
async def get_all_suspicious_activities(
    skip: int = 0,
    limit: int = 20,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> List[SuspiciousActivityResponse]:
    """
    Get all suspicious activities (admin only).
    """
    activities = await user_activity.get_all_suspicious_activities(
        skip=skip, limit=limit
    )
    return [SuspiciousActivityResponse(**activity) for activity in activities]


@router.get(
    "/security/analytics",
)
async def get_security_analytics(
    days: int = Query(30, description="Days of data to analyze"),
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> Any:
    """
    Get analytics on suspicious activities (admin only).
    """
    return await user_activity.get_suspicious_activity_analytics(days)
