from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class WebhookPayload:
    """
    Structured webhook payload sent to tenant sites.

    This is the data that gets signed with HMAC-SHA256 and POSTed
    to the site's webhook_url.

    Attributes:
        event_type: Type of event (e.g., 'user.verified')
        site_id: Legacy integer id of the site this event belongs to
        user_id: Legacy integer Aegis user id
        email: The user's email address
        aegis_role: The user's Aegis role ('user' or 'admin')
        timestamp: Unix timestamp when the event occurred
        site_uuid: Globally-unique id of the site this event belongs to. Source of truth.
        user_uuid: Globally-unique Aegis user id. Source of truth.
    """
    event_type: str
    site_id: int
    user_id: int
    email: str
    aegis_role: str
    timestamp: int
    site_uuid: Optional[str] = None
    user_uuid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert payload to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            'event_type': self.event_type,
            'site_id': self.site_id,
            'user_id': self.user_id,
            'email': self.email,
            'aegis_role': self.aegis_role,
            'timestamp': self.timestamp,
        }
        if self.site_uuid is not None:
            result['site_uuid'] = self.site_uuid
        if self.user_uuid is not None:
            result['user_uuid'] = self.user_uuid
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebhookPayload':
        """Create webhook payload from dictionary."""
        return cls(
            event_type=data['event_type'],
            site_id=data['site_id'],
            user_id=data['user_id'],
            email=data['email'],
            aegis_role=data['aegis_role'],
            timestamp=data['timestamp'],
            site_uuid=data.get('site_uuid'),
            user_uuid=data.get('user_uuid'),
        )
