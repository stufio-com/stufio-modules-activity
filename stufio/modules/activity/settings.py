from stufio.core.setting_registry import (
    GroupMetadata, SubgroupMetadata, SettingMetadata, 
    SettingType, settings_registry
)


"""Register settings for this module"""
# Register a new group tab for this module
settings_registry.register_group(
    GroupMetadata(
        id="activity", 
        label="Users Activity", 
        icon="globe", 
        order=14,  
    )
)

# Register subgroups
settings_registry.register_subgroup(
    SubgroupMetadata(
        id="activity",
        group_id="activity",
        label="Activity",
        order=10
    ),
)

settings_registry.register_subgroup(
    SubgroupMetadata(
        id="rate_limiting",
        group_id="activity",
        label="Rate Limiting",
        order=20
    ),
)

# Register settings
settings_registry.register_setting(
    SettingMetadata(
        key="activity_IP_BLACKLIST_TTL",
        label="IP Blacklist TTL",
        description="The time-to-live for IP blacklisting",
        group="activity",
        subgroup="activity",
        type=SettingType.NUMBER,
        order=90,
        module="activity",
    )
)

settings_registry.register_setting(
    SettingMetadata(
        key="activity_RATE_LIMIT_IP_MAX_REQUESTS",
        label="IP Max Requests",
        description="The maximum number of requests per IP",
        group="activity",
        subgroup="rate_limiting",
        type=SettingType.NUMBER,
        order=10,
        module="activity"
    )
)

settings_registry.register_setting(
    SettingMetadata(
        key="activity_RATE_LIMIT_IP_WINDOW_SECONDS",
        label="IP Window Seconds",
        description="The time window for rate limiting",
        group="activity",
        subgroup="rate_limiting",
        type=SettingType.NUMBER,
        order=20,
        module="activity"
    )
)

settings_registry.register_setting(
    SettingMetadata(
        key="activity_RATE_LIMIT_USER_MAX_REQUESTS",
        label="User Max Requests",
        description="The maximum number of requests per user",
        group="activity",
        subgroup="rate_limiting",
        type=SettingType.NUMBER,
        order=30,
        module="activity"
    )
)

settings_registry.register_setting(
    SettingMetadata(
        key="activity_RATE_LIMIT_USER_WINDOW_SECONDS",
        label="User Window Seconds",
        description="The time window for rate limiting",
        group="activity",
        subgroup="rate_limiting",
        type=SettingType.NUMBER,
        order=40,
        module="activity"
    )
)

settings_registry.register_setting(
    SettingMetadata(
        key="activity_SECURITY_MAX_UNIQUE_IPS_PER_DAY",
        label="Max Unique IPs Per Day",
        description="The maximum number of unique IPs per day",
        group="activity",
        subgroup="rate_limiting",
        type=SettingType.SLIDER,
        order=50,
        module="activity",
        min=0,
        max=100,
    )
)

settings_registry.register_setting(
    SettingMetadata(
        key="activity_RATE_LIMIT_CONFIG_TTL",
        label="Config TTL",
        description="The time-to-live for rate limit configuration",
        group="activity",
        subgroup="rate_limiting",
        type=SettingType.SLIDER,
        order=70,
        module="activity",
        min=0,
        max=600,
    )
)

settings_registry.register_setting(
    SettingMetadata(
        key="activity_RATE_LIMIT_DECISION_TTL",
        label="Decision TTL",
        description="The time-to-live for rate limit decisions",
        group="activity",
        subgroup="rate_limiting",
        type=SettingType.SLIDER,
        order=80,
        module="activity",
        min=0,
        max=120,
    )
)
