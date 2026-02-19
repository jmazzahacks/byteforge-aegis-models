from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class VerificationTokenStatus:
    """
    Result of checking a verification token status.

    Only returned for valid tokens. Invalid tokens result in an error response.

    Attributes:
        password_required: Whether the user needs to set a password during verification
        email: The email address associated with the token
    """
    password_required: bool
    email: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'password_required': self.password_required,
            'email': self.email,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VerificationTokenStatus':
        """Create from dictionary."""
        return cls(
            password_required=data['password_required'],
            email=data['email'],
        )
