from fastapi import APIRouter

from stufio.api.admin import admin_router
from .activities import router as activities_router
from .admin_activities import router as admin_activities_router
from .security import router as security_router
from .admin_security import router as admin_security_router
from .rate_limits import router as rate_limits_router
from .admin_analytics import router as admin_analytics_router


api_router = APIRouter()

# Include routers
api_router.include_router(activities_router, tags=["activities"])
api_router.include_router(security_router, tags=["security"])
api_router.include_router(rate_limits_router, tags=["rate-limits"])

# Include admin routers
admin_router.include_router(admin_activities_router, tags=["activities"])
admin_router.include_router(admin_security_router, tags=["security"])
admin_router.include_router(admin_analytics_router, tags=["analytics"])

