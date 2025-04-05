from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from motor.core import AgnosticDatabase

from stufio import models
from stufio.api import deps
from stufio.schemas.msg import Msg
from ..schemas import (
    RateLimitOverride,
    RateLimitConfigCreate,
    RateLimitConfigUpdate,
    RateLimitConfigResponse,
    ViolationReport,
)
from ..crud.crud_rate_limit import crud_rate_limit
from stufio.core.config import get_settings

settings = get_settings()
router = APIRouter()


@router.get(
    "/rate-limits/configs", response_model=List[RateLimitConfigResponse]
)
async def admin_get_rate_limit_configs(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = False,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> List[RateLimitConfigResponse]:
    """
    Get all rate limit configurations.
    """
    configs = await crud_rate_limit.get_all_rate_limit_configs(
        skip=skip, 
        limit=limit,
        active_only=active_only
    )
    return configs


@router.post("/rate-limits/configs", response_model=RateLimitConfigResponse)
async def admin_create_rate_limit_config(
    config: RateLimitConfigCreate,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> RateLimitConfigResponse:
    """
    Create a new rate limit configuration.
    """
    created_config = await crud_rate_limit.create_rate_limit_config(
        endpoint=config.endpoint,
        max_requests=config.max_requests,
        window_seconds=config.window_seconds,
        bypass_roles=config.bypass_roles,
        description=config.description,
        active=config.active
    )

    return created_config


@router.put(
    "/rate-limits/configs/{config_id}", response_model=RateLimitConfigResponse
)
async def admin_update_rate_limit_config(
    config_id: str,
    config_update: RateLimitConfigUpdate,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> RateLimitConfigCreate:
    """
    Update a rate limit configuration.
    """
    updated_config = await crud_rate_limit.update_rate_limit_config(
        config_id=config_id,
        max_requests=config_update.max_requests,
        window_seconds=config_update.window_seconds,
        active=config_update.active,
        bypass_roles=config_update.bypass_roles,
        description=config_update.description
    )

    if not updated_config:
        raise HTTPException(status_code=404, detail="Rate limit configuration not found")

    return updated_config


@router.delete("/rate-limits/configs/{config_id}", response_model=Msg)
async def admin_delete_rate_limit_config(
    config_id: str,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> Msg:
    """
    Delete a rate limit configuration.
    """
    success = await crud_rate_limit.delete_rate_limit_config(config_id=config_id)

    if not success:
        raise HTTPException(status_code=404, detail="Rate limit configuration not found")

    return Msg(msg="Rate limit configuration deleted")


@router.post("/rate-limits/override", response_model=RateLimitOverride)
async def admin_create_rate_limit_override(
    override: RateLimitOverride = Body(...),
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> Any:
    """
    Create a rate limit override for a specific user.
    """
    created_override = await crud_rate_limit.create_user_override(
        user_id=override.user_id,
        path=override.path,
        max_requests=override.max_requests,
        window_seconds=override.window_seconds,
        expires_at=override.expires_at
    )

    return created_override


@router.get("/rate-limits/overrides", response_model=List[RateLimitOverride])
async def admin_get_rate_limit_overrides(
    user_id: Optional[str] = None,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> Any:
    """
    Get all rate limit overrides, optionally filtered by user_id.
    """
    overrides = await crud_rate_limit.get_overrides(user_id=user_id)
    return overrides


@router.delete("/rate-limits/override/{override_id}", response_model=Msg)
async def admin_delete_rate_limit_override(
    override_id: str,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> Msg:
    """
    Delete a rate limit override.
    """
    success = await crud_rate_limit.delete_override(override_id=override_id)
    if not success:
        raise HTTPException(status_code=404, detail="Override not found")

    return Msg(msg="Rate limit override deleted")


@router.get("/rate-limits/violations", response_model=List[ViolationReport])
async def admin_get_rate_limit_violations(
    skip: int = 0,
    limit: int = 50,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> List[ViolationReport]:
    """
    Get recent rate limit violations.
    """
    violations = await crud_rate_limit.get_violations(skip=skip, limit=limit)
    return violations
