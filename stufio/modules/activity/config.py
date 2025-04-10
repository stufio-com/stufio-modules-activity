"""
    This module contains the configuration settings for the activity module.
    It defines the settings related to rate limiting, security, and Redis configurations.
    These settings are registered with the core settings registry and can be accessed
    throughout the application."""
from stufio.core.config import ModuleSettings, get_settings

settings = get_settings()

class ActivitySettings(ModuleSettings):
    # Rate limiting settings
    RATE_LIMIT_IP_MAX_REQUESTS: int = 100
    RATE_LIMIT_IP_WINDOW_SECONDS: int = 60
    RATE_LIMIT_USER_MAX_REQUESTS: int = 300
    RATE_LIMIT_USER_WINDOW_SECONDS: int = 60
    SECURITY_MAX_UNIQUE_IPS_PER_DAY: int = 5

    # Redis settings for rate limiting
    RATE_LIMIT_REDIS_PREFIX: str = "ratelimit:"
    RATE_LIMIT_CONFIG_TTL: int = 120 # 2 minutes
    RATE_LIMIT_DECISION_TTL: int = 30 # 30 seconds
    IP_BLACKLIST_TTL: int = 86400  # 1 day
    

# Register these settings with the core
settings.register_module_settings("activity", ActivitySettings)
