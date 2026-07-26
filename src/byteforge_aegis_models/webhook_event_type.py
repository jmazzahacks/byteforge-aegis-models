"""Webhook event type enumeration."""
from enum import Enum


class WebhookEventType(str, Enum):
    """
    Webhook event types sent to tenant sites.

    Values:
        USER_VERIFIED: A user completed email verification
        USER_DELETED: A user was deleted from Aegis
    """
    USER_VERIFIED = 'user.verified'
    USER_DELETED = 'user.deleted'
