from fastapi import FastAPI
from typing import List, Any, Tuple
import logging

from stufio.core.module_registry import ModuleInterface
from stufio.core.stufioapi import StufioAPI
from stufio.modules.events import KafkaModuleMixin
from .api import api_router
from .models import UserActivity, ClientFingerprint, RateLimit, UserSecurityProfile
from .middleware import ActivityTrackingMiddleware, RateLimitingMiddleware
from .__version__ import __version__

logger = logging.getLogger(__name__)


class ActivityModule(KafkaModuleMixin, ModuleInterface):
    """Activity tracking and rate limiting module."""

    version = __version__

    def register_routes(self, app: StufioAPI) -> None:
        """Register this module's routes with the FastAPI app."""
        # Register routes
        app.include_router(api_router, prefix=self.routes_prefix)

    def get_middlewares(self) -> List[Tuple]:
        """Return middleware classes for this module.

        Returns:
            List of (middleware_class, args, kwargs) tuples
        """
        return [(RateLimitingMiddleware, {}, {}), (ActivityTrackingMiddleware, {}, {})]
