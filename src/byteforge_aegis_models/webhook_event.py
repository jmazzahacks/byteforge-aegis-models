from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class WebhookEvent:
    """
    Webhook delivery log record.

    Tracks every webhook delivery attempt for audit and debugging.

    One row per ATTEMPT, not per event. Retried events therefore have
    several rows sharing an event_id, which is why the row's own uuid and
    the event's id are separate fields — before retries existed they were
    the same value, and a second attempt would have collided on the
    primary key.

    Attributes:
        uuid: Identifier for this attempt row (UUIDv7)
        site_uuid: Globally-unique id of the site this webhook was sent for
        event_type: Type of event (e.g., 'user.verified')
        payload: JSON payload that was sent
        response_status: HTTP status code from the tenant's endpoint
        response_body: Response body from the tenant's endpoint
        success: Whether the delivery was successful (2xx response)
        created_at: Unix timestamp when the webhook was sent
        attempt: 1-based attempt number for this event
        event_id: The id carried in the payload, stable across attempts.
            This is the value a tenant reports, so it is what you grep by.
            Defaults to the row uuid for rows written before retries, where
            the two were identical.
    """
    uuid: str
    site_uuid: str
    event_type: str
    payload: str
    response_status: Optional[int]
    response_body: Optional[str]
    success: bool
    created_at: int
    attempt: int = 1
    event_id: Optional[str] = None

    def __post_init__(self) -> None:
        # Normalized once, here, so event_id is never None on a live object.
        # Rows written before retries existed put the event id in uuid, and
        # leaving the fallback to every read site would mean every caller
        # remembering it — and one of them eventually not.
        if self.event_id is None:
            self.event_id = self.uuid

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
            'attempt': self.attempt,
            'event_id': self.event_id,
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
            attempt=data.get('attempt', 1),
            # None falls back to uuid in __post_init__, which is what a
            # row written before retries existed means.
            event_id=data.get('event_id'),
        )
