from faststream.kafka.fastapi import Logger
from ..events import UserActivityEvent
from ..schemas.activity import UserActivityEventPayload
from stufio.modules.events import stufio_event_subscriber, BaseEventMessage
from ..crud import crud_activity


@stufio_event_subscriber(UserActivityEvent)
async def handle_user_activity(
    event: BaseEventMessage[UserActivityEventPayload], logger: Logger
) -> None:
    """
    Handle user activity events and record them in the database.
    This consumer replaces the direct database writes from the middleware.
    """
    try:
        if not event.payload:
            logger.warning("Received user activity event with no payload")
            return

        # Extract data from the event
        user_id = event.actor.id if event.actor and event.actor.id != "anonymous" else None

        # Record the activity in the database
        await crud_activity.create_activity(
            user_id=user_id,
            path=event.payload.path,
            method=event.payload.method,
            client_ip=event.payload.client_ip,
            user_agent=event.payload.user_agent,
            status_code=event.payload.status_code,
            process_time=event.payload.process_time
        )

        # Check for suspicious activity
        is_suspicious = await crud_activity.check_suspicious_activity(
            user_id=user_id,
            client_ip=event.payload.client_ip,
            user_agent=event.payload.user_agent,
            path=event.payload.path,
            method=event.payload.method,
            status_code=event.payload.status_code,
        )

        if is_suspicious:
            logger.warning(
                f"Suspicious activity detected for user {user_id} from {event.payload.client_ip}"
            )

        logger.info(f"Recorded activity for path {event.payload.path}")

    except Exception as e:
        logger.error(f"Error processing user activity event: {e}", exc_info=True)
