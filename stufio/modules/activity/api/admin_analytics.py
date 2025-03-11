from typing import Dict, Any, List
from clickhouse_connect.driver.asyncclient import AsyncClient
from fastapi import APIRouter, Depends, Query

from stufio.api import deps
from ..schemas import PathStatistics, ErrorReport
from ..crud.crud_analytics import crud_analytics

router = APIRouter()


@router.get("/activities/path-report")
async def get_path_statistics(
    path: str = Query(None, min_length=1, max_length=127),
    hours: int = Query(24, ge=1, le=168),
    db: AsyncClient = Depends(deps.get_clickhouse),
    current_user=Depends(deps.get_current_active_superuser),
) -> List[PathStatistics]:
    """
    Get statistics for API paths
    """
    return await crud_analytics.get_path_statistics(db=db, path=path, hours=hours)


@router.get("/activities/error-report")
async def get_error_report(
    days: int = Query(1, ge=1, le=30),
    db: AsyncClient = Depends(deps.get_clickhouse),
    current_user=Depends(deps.get_current_active_superuser),
) -> List[ErrorReport]:
    """
    Get report of API errors
    """
    return await crud_analytics.get_error_report(db=db, days=days)
