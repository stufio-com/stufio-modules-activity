from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import time
import asyncio
import logging

from stufio.api import deps
from stufio.db.clickhouse import ClickhouseDatabase
from ..crud import crud_activity
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
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.replace("Bearer ", "")
                try:
                    token_data = deps.get_token_payload(token)
                    user_id = token_data.sub
                except:
                    pass

            # Use asyncio.create_task to run in background
            asyncio.create_task(
                self._record_activity(
                    user_id=str(user_id) if user_id else None,
                    path=path,
                    method=method,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    status_code=status_code,
                    process_time=process_time
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

    async def _record_activity(
        self,
        user_id,
        path,
        method,
        client_ip,
        user_agent,
        status_code,
        process_time,
    ):
        """Record the API activity in MongoDB and/or ClickHouse"""
        try:
            clickhouse_db = await ClickhouseDatabase()

            # Now use the db and current_user
            await crud_activity.create_activity(
                db=clickhouse_db,
                user_id=user_id,
                path=path,
                method=method,
                client_ip=client_ip,
                user_agent=user_agent,
                status_code=status_code,
                process_time=process_time
            )

            # Check for suspicious activity
            await self._check_suspicious_activity(
                clickhouse_db=clickhouse_db,
                user_id=user_id,
                client_ip=client_ip,
                user_agent=user_agent,
                path=path,
                method=method,
                status_code=status_code,
            )
        except Exception as e:
            logger.error(f"Failed to record activity: {str(e)}")

    async def _check_suspicious_activity(
        self,
        clickhouse_db,
        user_id,
        client_ip,
        user_agent,
        path,
        method,
        status_code
    ):
        """Check if this activity appears suspicious"""
        try:
            is_suspicious = await crud_activity.check_suspicious_activity(
                clickhouse_db=clickhouse_db,
                user_id=user_id,
                client_ip=client_ip,
                user_agent=user_agent,
                path=path,
                method=method,
                status_code=status_code,
            )

            if is_suspicious:
                logger.warning(
                    f"Suspicious activity detected for user {user_id} from {client_ip}"
                )
        except Exception as e:
            logger.error(f"Failed to check for suspicious activity: {str(e)}")
