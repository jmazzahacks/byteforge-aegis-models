from dataclasses import dataclass
from typing import Any, Dict

from byteforge_aegis_models.user import User


@dataclass
class VerificationResult:
    """
    Result of email verification containing user and redirect URL.

    Attributes:
        user: The verified user
        redirect_url: URL to redirect to after verification
    """
    user: User
    redirect_url: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert verification result to dictionary."""
        return {
            'user': self.user.to_dict(),
            'redirect_url': self.redirect_url,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VerificationResult':
        """Create verification result from dictionary."""
        return cls(
            user=User.from_dict(data['user']),
            redirect_url=data['redirect_url'],
        )
