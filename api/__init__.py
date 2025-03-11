from fastapi import APIRouter
from .activities import router as activities_router
from .admin_activities import router as admin_activities_router
from .security import router as security_router
from .admin_security import router as admin_security_router
from .rate_limits import router as rate_limits_router
from .admin_analytics import router as admin_analytics_router

from app.config import settings

api_router = APIRouter()
api_router.include_router(activities_router, prefix="", tags=["activities"])
api_router.include_router(security_router, prefix="", tags=["security"])
api_router.include_router(rate_limits_router, prefix="", tags=["rate-limits"])

api_router.include_router(admin_activities_router, prefix=settings.API_ADMIN_STR, tags=["activities", "admin"])
api_router.include_router(admin_security_router, prefix=settings.API_ADMIN_STR, tags=["security", "admin"])
api_router.include_router(admin_analytics_router, prefix=settings.API_ADMIN_STR, tags=["analytics", "admin"])
