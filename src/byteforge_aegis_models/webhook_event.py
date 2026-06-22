from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class WebhookEvent:
    """
    Webhook delivery log record.

    Tracks every webhook delivery attempt for audit and debugging.

    Attributes:
        id: Legacy integer event identifier (read-only during the UUID
            migration; will be removed once all tenants migrate to uuid)
        site_id: Legacy integer id of the site this webhook was sent for
        uuid: Globally-unique event identifier (UUIDv7). Source of truth.
        site_uuid: Globally-unique id of the site this webhook was sent for
        event_type: Type of event (e.g., 'user.verified')
        payload: JSON payload that was sent
        response_status: HTTP status code from the tenant's endpoint
        response_body: Response body from the tenant's endpoint
        success: Whether the delivery was successful (2xx response)
        created_at: Unix timestamp when the webhook was sent
    """
    id: int
    site_id: int
    event_type: str
    payload: str
    response_status: Optional[int]
    response_body: Optional[str]
    success: bool
    created_at: int
    uuid: Optional[str] = None
    site_uuid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert webhook event to dictionary."""
        return {
            'id': self.id,
            'site_id': self.site_id,
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
            id=data.get('id', 0),
            site_id=data['site_id'],
            uuid=data.get('uuid'),
            site_uuid=data.get('site_uuid'),
            event_type=data['event_type'],
            payload=data['payload'],
            response_status=data.get('response_status'),
            response_body=data.get('response_body'),
            success=data['success'],
            created_at=data['created_at'],
        )
