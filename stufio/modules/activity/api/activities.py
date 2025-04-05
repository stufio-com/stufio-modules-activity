from fastapi import APIRouter, Depends
from stufio.crud.clickhouse_base import AsyncClient
from stufio.schemas.base_schema import PaginatedResponse
from motor.core import AgnosticDatabase

from stufio import models
from stufio.api import deps
from ..schemas import UserActivityResponse
from ..crud import crud_activity


router = APIRouter()


@router.get(
    "/user/activities", response_model=PaginatedResponse[UserActivityResponse]
)
async def read_own_activities(
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> PaginatedResponse[UserActivityResponse]:
    """
    Retrieve current user's activity history.
    """
    activities, total = await crud_activity.get_user_activities(
        user_id=str(current_user.id), skip=skip, limit=limit
    )
    return PaginatedResponse(items=activities, total=total, skip=skip, limit=limit)
