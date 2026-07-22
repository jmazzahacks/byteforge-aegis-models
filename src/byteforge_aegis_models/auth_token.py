from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class AuthToken:
    """
    Authentication token model for managing user sessions.

    These tokens prove a user is logged in and are included in the Authorization
    header for protected API endpoints.

    Note: site_uuid and created_at are Optional because the API login/refresh
    responses omit them (per AuthTokenResponseSchema).

    Attributes:
        token: Unique secure token string
        user_uuid: Globally-unique id of the user this token belongs to
        expires_at: Unix timestamp when the token expires
        site_uuid: Globally-unique id of the site this token belongs to (omitted in API responses)
        created_at: Unix timestamp when the token was created (omitted in API responses)
    """
    token: str
    user_uuid: str
    expires_at: int
    site_uuid: Optional[str] = None
    created_at: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert auth token model to dictionary."""
        result: Dict[str, Any] = {
            'token': self.token,
            'user_uuid': self.user_uuid,
            'expires_at': self.expires_at,
        }
        if self.site_uuid is not None:
            result['site_uuid'] = self.site_uuid
        if self.created_at is not None:
            result['created_at'] = self.created_at
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthToken':
        """Create auth token model from dictionary."""
        return cls(
            token=data['token'],
            user_uuid=data['user_uuid'],
            expires_at=data['expires_at'],
            site_uuid=data.get('site_uuid'),
            created_at=data.get('created_at'),
        )
