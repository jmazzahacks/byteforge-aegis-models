from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class RefreshToken:
    """
    Refresh token model for long-lived session management.

    These tokens are used to obtain new auth tokens without re-authentication.
    They have longer expiration than auth tokens and support rotation for security.

    Note: family_id, created_at, used_at, and revoked are Optional because the
    API login/refresh responses omit them (per RefreshTokenResponseSchema).
    They are internal rotation/revocation state and intentionally not exposed
    to clients. They are populated when the model is loaded from the database.

    Attributes:
        token: Unique secure token string
        site_id: ID of the site this token belongs to
        user_id: ID of the user this token belongs to
        expires_at: Unix timestamp when the token expires
        family_id: Groups related rotated tokens for revocation (omitted in API responses)
        created_at: Unix timestamp when the token was created (omitted in API responses)
        used_at: Unix timestamp when token was exchanged (omitted in API responses)
        revoked: Whether the token has been revoked (omitted in API responses)
    """
    token: str
    site_id: int
    user_id: int
    expires_at: int
    family_id: Optional[str] = None
    created_at: Optional[int] = None
    used_at: Optional[int] = None
    revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert refresh token model to dictionary."""
        result: Dict[str, Any] = {
            'token': self.token,
            'site_id': self.site_id,
            'user_id': self.user_id,
            'expires_at': self.expires_at,
        }
        if self.family_id is not None:
            result['family_id'] = self.family_id
        if self.created_at is not None:
            result['created_at'] = self.created_at
        if self.used_at is not None:
            result['used_at'] = self.used_at
        if self.revoked:
            result['revoked'] = self.revoked
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RefreshToken':
        """Create refresh token model from dictionary."""
        return cls(
            token=data['token'],
            site_id=data['site_id'],
            user_id=data['user_id'],
            expires_at=data['expires_at'],
            family_id=data.get('family_id'),
            created_at=data.get('created_at'),
            used_at=data.get('used_at'),
            revoked=data.get('revoked', False),
        )
