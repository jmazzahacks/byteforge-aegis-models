from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class WebhookEvent:
    """
    Webhook delivery log record.

    Tracks every webhook delivery attempt for audit and debugging.

    Attributes:
        uuid: Globally-unique event identifier (UUIDv7)
        site_uuid: Globally-unique id of the site this webhook was sent for
        event_type: Type of event (e.g., 'user.verified')
        payload: JSON payload that was sent
        response_status: HTTP status code from the tenant's endpoint
        response_body: Response body from the tenant's endpoint
        success: Whether the delivery was successful (2xx response)
        created_at: Unix timestamp when the webhook was sent
    """
    uuid: str
    site_uuid: str
    event_type: str
    payload: str
    response_status: Optional[int]
    response_body: Optional[str]
    success: bool
    created_at: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert webhook event to dictionary."""
        return {
            'uuid': self.uuid,
            'site_uuid': self.site_uuid,
            'event_type': self.event_type,
            'payload': self.payload,
            'response_status': self.response_status,
            'response_body': self.response_body,
            'success': self.success,
            'created_at': self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebhookEvent':
        """Create webhook event from dictionary."""
        return cls(
            uuid=data['uuid'],
            site_uuid=data['site_uuid'],
            event_type=data['event_type'],
            payload=data['payload'],
            response_status=data.get('response_status'),
            response_body=data.get('response_body'),
            success=data['success'],
            created_at=data['created_at'],
        )
