from fastapi import FastAPI
from typing import List, Callable, Any, Tuple

from stufio.core.module_registry import ModuleInterface
from .api import api_router
from .models import UserActivity, ClientFingerprint, RateLimit, UserSecurityProfile
from .middleware import ActivityTrackingMiddleware, RateLimitingMiddleware
from .__version__ import __version__
from .config import ActivitySettings


class ActivityModule(ModuleInterface):
    """Activity tracking and rate limiting module."""

    __version__ = __version__

    def register_routes(self, app: FastAPI, router_prefix: str = None) -> None:
        """Register this module's routes with the FastAPI app."""
        # Register routes
        app.include_router(api_router, prefix=router_prefix)

    def get_middlewares(self) -> List[Tuple]:
        """Return middleware classes for this module.

        Returns:
            List of (middleware_class, args, kwargs) tuples
        """
        return [(RateLimitingMiddleware, {}, {}), (ActivityTrackingMiddleware, {}, {})]

    # For backwards compatibility
    def register(self, app: FastAPI) -> None:
        """Legacy registration method."""
        self.register_routes(app)
        # Don't add middleware here anymore

    def get_models(self) -> List[Any]:
        """Return this module's database models."""
        return [UserActivity, ClientFingerprint, RateLimit, UserSecurityProfile]
