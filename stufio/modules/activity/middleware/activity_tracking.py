from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import time
import asyncio
import logging
import uuid

from stufio.api import deps
from ..events import UserActivityEvent
from ..schemas.activity import UserActivityEventPayload
from stufio.modules.events import ActorType
from stufio.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

class ActivityTrackingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        # Start timing the request
        start_time = time.time()

        # Extract basic request info
        path = request.url.path
        method = request.method
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")

        # Skip tracking for certain paths
        if path in ["/metrics", "/health", "/api/v1/docs", "/api/v1/openapi.json"]:
            return await call_next(request)

        # Process the request
        response = await call_next(request)

        # Record processing time
        process_time = time.time() - start_time

        # Collect response data
        status_code = response.status_code

        # Record activity asynchronously (don't block the response)
        if path.startswith(settings.API_V1_STR):
            user_id = None
            is_authenticated = False
            auth_header = request.headers.get("authorization")

            if (
                auth_header
                and auth_header.startswith("Bearer ")
                and path not in [settings.API_V1_STR + "/login/claim"]
            ):
                token = auth_header.replace("Bearer ", "")
                try:
                    token_data = deps.get_token_payload(token)
                    user_id = token_data.sub
                    is_authenticated = True
                except:
                    pass

            # Use asyncio.create_task to run in background
            asyncio.create_task(
                self._publish_activity_event(
                    user_id=str(user_id) if user_id else None,
                    path=path,
                    method=method,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    status_code=status_code,
                    process_time=process_time,
                    is_authenticated=is_authenticated
                )
            )

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP from request headers"""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Get the first IP if multiple are provided
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def _publish_activity_event(
        self,
        user_id,
        path,
        method,
        client_ip,
        user_agent,
        status_code,
        process_time,
        is_authenticated
    ):
        """Publish a user activity event instead of directly writing to the database"""
        try:
            # Create a correlation ID for tracking
            correlation_id = str(uuid.uuid4())

            # Publish the activity event
            await UserActivityEvent.publish(
                entity_id=user_id or f"anon-{client_ip}",
                actor_type=ActorType.USER if user_id else ActorType.SYSTEM,
                actor_id=user_id or "anonymous",
                correlation_id=correlation_id,
                payload=UserActivityEventPayload(
                    path=path,
                    method=method,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    status_code=status_code,
                    process_time=process_time,
                    is_authenticated=is_authenticated,
                ),
                metrics={"processing_time_ms": int(process_time * 1000)},
            )

            logger.debug(f"Published activity event for path {path}")

        except Exception as e:
            logger.error(f"Failed to publish activity event: {str(e)}", exc_info=True)
