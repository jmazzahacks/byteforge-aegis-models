from dataclasses import dataclass
from typing import Any, Dict

from byteforge_aegis_models.user_role import UserRole


@dataclass
class User:
    """
    User model representing a registered user account.

    Users are scoped to a specific site (multi-tenant).
    Email is unique per site, not globally.

    Note: password_hash is excluded from this shared model since
    the API never returns it to clients.

    Attributes:
        id: Unique user identifier
        site_id: The site/tenant this user belongs to
        email: User's email address (unique per site)
        is_verified: Whether the user's email has been verified
        role: User role (USER or ADMIN)
        created_at: Unix timestamp when the user was created
        updated_at: Unix timestamp when the user was last updated
    """
    id: int
    site_id: int
    email: str
    is_verified: bool
    role: UserRole
    created_at: int
    updated_at: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert user model to dictionary."""
        return {
            'id': self.id,
            'site_id': self.site_id,
            'email': self.email,
            'is_verified': self.is_verified,
            'role': self.role.value,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user model from dictionary."""
        return cls(
            id=data['id'],
            site_id=data['site_id'],
            email=data['email'],
            is_verified=data['is_verified'],
            role=UserRole(data['role']),
            created_at=data['created_at'],
            updated_at=data['updated_at'],
        )
