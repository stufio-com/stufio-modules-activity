"""
Event consumers for the activity module.

This package contains consumers that handle various events related to user activity.
"""

from stufio.core.config import get_settings

settings = get_settings()

if settings.events_APP_CONSUME_ROUTES:

    # Import all consumers to ensure they're registered
    # from . import activity_consumer
    from . import api_request_consumer

