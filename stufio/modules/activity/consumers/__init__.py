from stufio.core.config import get_settings

settings = get_settings()

if settings.events_APP_CONSUME_ROUTES:

    # Import all consumers to ensure they're registered
    from .activity_consumer import handle_user_activity