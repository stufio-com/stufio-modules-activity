from stufio.modules.events import EventDefinition
from .schemas.activity import UserActivityEventPayload

class UserActivityEvent(EventDefinition[UserActivityEventPayload]):
    """Event triggered when a user performs an activity in the system."""
    name = "user.activity"
    entity_type = "user"
    action = "activity"
    require_actor = False
    require_entity = False
    description = "Triggered when a user performs an activity in the system"
    
    high_volume = True  # This will use a dedicated topic
    partitions = 16  # Suggest higher partition count for this topic
