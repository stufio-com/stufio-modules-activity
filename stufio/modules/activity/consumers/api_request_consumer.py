"""
Consumer for API request events from the events module.

This consumer processes API request events from Kafka and stores them 
as user activity in the activity module's database
"""
from aiokafka import metrics
from faststream.kafka.fastapi import Logger
from typing import Optional, Dict, Any

from stufio.modules.events import (
    HandlerResponse,
    stufio_event_subscriber,
    BaseEventMessage,
    APIRequestEvent,
    APIRequestPayload,
)
from ..crud import crud_activity

@stufio_event_subscriber(APIRequestEvent)  # Changed decorator
async def handle_api_request_event(
    event: BaseEventMessage[APIRequestPayload], logger: Logger
) -> HandlerResponse:
    """
    Handle API request events and record them as user activity.
    """
    try:
        if not event.payload:
            logger.warning("Received API request event with no payload")
            return HandlerResponse(
                metrics={"success": False, "reason": "no_payload"}
            )

        # Extract data from the event payload
        payload = event.payload
        
        # Extract user ID, handling anonymous users
        user_id: Optional[str] = None
        if payload.user_id and not payload.user_id.startswith("anon-"):
            user_id = payload.user_id

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
            
        # Return custom metrics that will be saved in event_metrics
        return HandlerResponse(
            metrics={
                "success": True,
                "user_id": user_id,
                "suspicious_activity": is_suspicious
            },
        )

    except Exception as e:
        logger.error(f"Error processing API request event: {e}", exc_info=True)
        raise  # Re-raise so metrics will track the error
