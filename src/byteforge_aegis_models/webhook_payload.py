from dataclasses import dataclass
from typing import Any, Dict

from byteforge_aegis_models.webhook_event_type import WebhookEventType


@dataclass
class WebhookPayload:
    """
    Structured webhook payload sent to tenant sites.

    This is the data that gets signed with HMAC-SHA256 and POSTed
    to the site's webhook_url.

    Attributes:
        event_type: Type of event (USER_VERIFIED or USER_DELETED)
        site_uuid: Globally-unique id of the site this event belongs to
        user_uuid: Globally-unique Aegis user id
        email: The user's email address
        aegis_role: The user's Aegis role ('user' or 'admin')
        timestamp: Unix timestamp when the event occurred
    """
    event_type: WebhookEventType
    site_uuid: str
    user_uuid: str
    email: str
    aegis_role: str
    timestamp: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert payload to dictionary for JSON serialization."""
        return {
            'event_type': self.event_type.value,
            'site_uuid': self.site_uuid,
            'user_uuid': self.user_uuid,
            'email': self.email,
            'aegis_role': self.aegis_role,
            'timestamp': self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebhookPayload':
        """Create webhook payload from dictionary."""
        return cls(
            event_type=WebhookEventType(data['event_type']),
            site_uuid=data['site_uuid'],
            user_uuid=data['user_uuid'],
            email=data['email'],
            aegis_role=data['aegis_role'],
            timestamp=data['timestamp'],
        )
