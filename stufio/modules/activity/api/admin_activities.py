from typing import List
from clickhouse_connect.driver.asyncclient import AsyncClient
from fastapi import APIRouter, Depends, Query
from stufio.schemas.base_schema import PaginatedResponse
from motor.core import AgnosticDatabase

from stufio import models
from stufio.api import deps
from ..schemas import UserActivityResponse, UserActivitySummary
from ..crud import crud_activity

router = APIRouter()


@router.get(
    "/activities/{user_id}", response_model=PaginatedResponse[UserActivityResponse]
)
async def read_user_activities(
    user_id: str,
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(deps.get_current_active_superuser),
) -> PaginatedResponse[UserActivityResponse]:
    """
    Retrieve activities for a specific user.
    Only for superusers.
    """
    activities, total = await crud_activity.get_user_activities(
        user_id=user_id, skip=skip, limit=limit
    )
    return PaginatedResponse(items=activities, total=total, skip=skip, limit=limit)


@router.get(
    "/activities/{user_id}/summary", response_model=List[UserActivitySummary]
)
async def get_crud_activity_summary(
    user_id: str,
    days: int = Query(7, ge=1, le=90),
    current_user=Depends(deps.get_current_active_superuser),
) -> List[UserActivitySummary]:
    """
    Get summary of user activity over time
    """
    return await crud_activity.get_user_activity_summary(
        user_id=user_id, days=days
    )
