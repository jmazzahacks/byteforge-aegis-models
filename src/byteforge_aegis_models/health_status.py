from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class HealthStatus:
    """
    Response from the API health check endpoint.

    Attributes:
        status: Health status string (e.g., 'ok')
    """
    status: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {'status': self.status}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HealthStatus':
        """Create from dictionary."""
        return cls(status=data['status'])
