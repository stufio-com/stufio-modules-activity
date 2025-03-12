from typing import Any, List, Dict
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from motor.core import AgnosticDatabase
from clickhouse_connect.driver.asyncclient import AsyncClient

from stufio import models
from stufio.api import deps
from stufio.schemas import Msg
from ..schemas import (
    UserSecurityProfileResponse,
    SuspiciousActivityResponse,
    TrustedDeviceResponse,
    TrustedDeviceCreate
)
from ..crud.crud_activity import user_activity
from ..models import UserSecurityProfile

router = APIRouter()


@router.get("/user/security/profile", response_model=UserSecurityProfileResponse)
async def get_security_profile(
    db: AgnosticDatabase = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> UserSecurityProfileResponse:
    """
    Get the current user's security profile with known devices.
    """
    security_profile = await user_activity.get_security_profile(
        db, user_id=str(current_user.id)
    )
    if not security_profile:
        # Create a default profile if none exists
        security_profile = UserSecurityProfile(user_id=str(current_user.id))

    return UserSecurityProfileResponse(**security_profile.model_dump())


@router.get(
    "/user/security/trusted-devices", response_model=List[TrustedDeviceResponse]
)
async def get_trusted_devices(
    db: AgnosticDatabase = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> List[TrustedDeviceResponse]:
    """
    Get the list of trusted devices for the current user.
    """
    security_profile = await user_activity.get_security_profile(
        db, user_id=str(current_user.id)
    )
    if not security_profile:
        return []

    return [
        TrustedDeviceResponse(**device.model_dump())
        for device in security_profile.known_fingerprints
    ]


@router.post("/user/security/trusted-devices", response_model=TrustedDeviceResponse)
async def add_trusted_device(
    device: TrustedDeviceCreate = Body(...),
    db: AgnosticDatabase = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> TrustedDeviceResponse:
    """
    Add a new trusted device manually.
    """
    new_device = await user_activity.add_trusted_device(
        db, user_id=str(current_user.id), device=device
    )
    return TrustedDeviceResponse(**new_device)


@router.delete("/user/security/trusted-devices/{device_id}", response_model=Msg)
async def remove_trusted_device(
    device_id: str,
    db: AgnosticDatabase = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Msg:
    """
    Remove a device from the trusted list.
    """
    success = await user_activity.remove_trusted_device(
        db, user_id=str(current_user.id), device_id=device_id
    )
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")

    return Msg(msg="Device removed from trusted list")


@router.get(
    "/user/security/suspicious-activities",
    response_model=List[SuspiciousActivityResponse],
)
async def get_suspicious_activities(
    skip: int = 0,
    limit: int = 20,
    clickhouse_db: AsyncClient = Depends(deps.get_clickhouse),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> List[SuspiciousActivityResponse]:
    """
    Get suspicious activities for the current user.
    """
    activities = await user_activity.get_suspicious_activities(
        clickhouse_db, user_id=str(current_user.id), skip=skip, limit=limit
    )
    return [SuspiciousActivityResponse(**activity) for activity in activities]
