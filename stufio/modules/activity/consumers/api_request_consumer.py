"""
Consumer for API request events from the events module.

This consumer processes API request events from Kafka and stores them 
as user activity in the activity module's database
"""
from faststream.kafka.fastapi import Logger
from typing import Optional, Dict, Any

from stufio.modules.events import (
    stufio_event_subscriber,
    BaseEventMessage,
    APIRequestEvent,
    APIRequestPayload,
)

from ..crud import crud_activity


@stufio_event_subscriber(APIRequestEvent)
async def handle_api_request_event(
    event: BaseEventMessage[APIRequestPayload], logger: Logger
) -> None:
    """
    Handle API request events and record them as user activity.
    
    This consumer processes events from the events module's EventTrackingMiddleware
    and stores them in the activity module's database, replacing the previous
    middleware-based tracking.
    """
    try:
        if not event.payload:
            logger.warning("Received API request event with no payload")
            return

        # Extract data from the event payload
        payload = event.payload
        
        # Extract user ID, handling anonymous users
        user_id: Optional[str] = None
        if payload.user_id and not payload.user_id.startswith("anon-"):
            user_id = payload.user_id

        # Extract detailed metrics if available
        metrics = event.metrics
        
        # Log the metrics for debugging - safely accessing Pydantic model fields using getattr instead of .get()
        db_metrics = {
            "total_time_ms": getattr(metrics, "total_time_ms", 0) if metrics else 0,
            "mongo_time_ms": (getattr(metrics, "mongodb", {}) or {}).get("time_ms", 0) if metrics else 0,
            "clickhouse_time_ms": (getattr(metrics, "clickhouse", {}) or {}).get("time_ms", 0) if metrics else 0,
            "redis_time_ms": (getattr(metrics, "redis", {}) or {}).get("time_ms", 0) if metrics else 0
        }
        
        if any(db_metrics.values()):
            # Only log if we have meaningful metrics
            logger.debug(f"Request metrics for {payload.path}: {db_metrics}")

        # Record the activity in the database
        await crud_activity.create_activity(
            user_id=user_id,
            path=payload.path,
            method=payload.method,
            client_ip=payload.remote_ip or "unknown",
            user_agent=payload.user_agent or "",
            status_code=payload.status_code,
            process_time=payload.duration_ms / 1000  # Convert ms to seconds
        )

        # Check for suspicious activity based on the request
        is_suspicious = await crud_activity.check_suspicious_activity(
            user_id=user_id,
            client_ip=payload.remote_ip or "unknown",
            user_agent=payload.user_agent or "",
            path=payload.path,
            method=payload.method,
            status_code=payload.status_code,
        )

        if is_suspicious:
            logger.warning(
                f"Suspicious activity detected for user {user_id or 'anonymous'} from {payload.remote_ip}"
            )

        logger.info(f"Recorded activity for path {payload.path}")

    except Exception as e:
        logger.error(f"Error processing API request event: {e}", exc_info=True)
