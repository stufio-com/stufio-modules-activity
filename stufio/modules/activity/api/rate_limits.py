from typing import List, Dict
from fastapi import APIRouter, Depends
from motor.core import AgnosticDatabase

from stufio import models
from stufio.api import deps
from ..schemas import RateLimitStatus
from ..crud import crud_rate_limit
from stufio.core.config import get_settings

settings = get_settings()
router = APIRouter()


@router.get("/user/rate-limits", response_model=Dict[str, RateLimitStatus])
async def get_rate_limit_status(
    clickhouse_db = Depends(deps.get_clickhouse),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> List[Dict[str, RateLimitStatus]]:
    """
    Get the current rate limit status for the authenticated user.
    Shows how many requests remain for different endpoints.
    """
    user_id = str(current_user.id)

    # Get common endpoints status
    status = {}

    # Overall API limit
    status["api"] = await crud_rate_limit.get_user_limit_status(
        user_id=user_id,
        path="*",
        max_requests=settings.activity_RATE_LIMIT_USER_MAX_REQUESTS,
        window_seconds=settings.activity_RATE_LIMIT_USER_WINDOW_SECONDS,
    )

    # Check specific endpoint limits from MongoDB
    configs = await crud_rate_limit.get_all_rate_limit_configs(active_only=True)
    for config in configs:
        endpoint = config.endpoint
        status[endpoint] = await crud_rate_limit.get_user_limit_status(
            user_id=user_id,
            path=endpoint,
            max_requests=config.max_requests,
            window_seconds=config.window_seconds
        )

    return status
