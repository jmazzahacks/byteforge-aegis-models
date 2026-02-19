from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class EmailChangeResponse:
    """
    Response from requesting an email change.

    Attributes:
        message: Confirmation message
        token: The email change verification token
    """
    message: str
    token: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {'message': self.message, 'token': self.token}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmailChangeResponse':
        """Create from dictionary."""
        return cls(message=data['message'], token=data['token'])
