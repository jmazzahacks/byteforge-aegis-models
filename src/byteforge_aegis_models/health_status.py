from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class HealthStatus:
    """
    Response from the API health check endpoint.

    Attributes:
        status: Health status string (e.g. 'healthy')
        service: Which service answered (e.g. 'auth-service'). None when
            talking to a backend older than v66, which did not report it.
        version: The backend's deployed build number as a string (e.g. '68').
            None on pre-v66 backends.

    `service` and `version` are Optional rather than required on purpose.
    The backend has reported all three fields since v66, but a client may
    legitimately be pointed at an older deployment, and a health check is the
    one call that must not raise — it is what orchestrators restart
    containers on. A missing field reads as None instead of a KeyError.

    They were originally omitted here, so `from_dict` silently discarded the
    very version that /api/health was extended to expose: any consumer asking
    "which build is live?" through this model got `status` and nothing else,
    and had to bypass the client with a raw GET to find out.
    """
    status: str
    service: Optional[str] = None
    version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'status': self.status,
            'service': self.service,
            'version': self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HealthStatus':
        """Create from dictionary."""
        return cls(
            status=data['status'],
            service=data.get('service'),
            version=data.get('version'),
        )
