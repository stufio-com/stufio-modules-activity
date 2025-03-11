from typing import List, Dict
from fastapi import APIRouter, Depends
from motor.core import AgnosticDatabase

from stufio import models
from stufio.api import deps
from app.config import settings
from ..schemas import RateLimitStatus
from ..crud import crud_rate_limit

router = APIRouter()


@router.get("/user/rate-limits", response_model=Dict[str, RateLimitStatus])
async def get_rate_limit_status(
    db: AgnosticDatabase = Depends(deps.get_db),
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
        db, 
        clickhouse_db,
        user_id=user_id,
        path="*",
        max_requests=settings.RATE_LIMIT_USER_MAX_REQUESTS,
        window_seconds=settings.RATE_LIMIT_USER_WINDOW_SECONDS
    )

    # Check specific endpoint limits from MongoDB
    configs = await crud_rate_limit.get_all_rate_limit_configs(db, active_only=True)
    for config in configs:
        endpoint = config["endpoint"]
        status[endpoint] = await crud_rate_limit.get_user_limit_status(
            db,
            clickhouse_db,
            user_id=user_id,
            path=endpoint,
            max_requests=config.get("max_requests", 100),
            window_seconds=config.get("window_seconds", 60)
        )

    return status
