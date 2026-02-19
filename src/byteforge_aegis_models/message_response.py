from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class MessageResponse:
    """
    Simple API response containing a message string.

    Used for acknowledgment responses like logout, password reset requests, etc.

    Attributes:
        message: The response message
    """
    message: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {'message': self.message}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageResponse':
        """Create from dictionary."""
        return cls(message=data['message'])
