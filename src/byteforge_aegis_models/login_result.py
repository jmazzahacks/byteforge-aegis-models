from dataclasses import dataclass
from typing import Any, Dict, Optional

from byteforge_aegis_models.auth_token import AuthToken
from byteforge_aegis_models.refresh_token import RefreshToken


@dataclass
class LoginResult:
    """
    Result of a successful login or token refresh operation.

    Attributes:
        auth_token: Short-lived token for API authentication
        refresh_token: Long-lived token for refreshing auth tokens
    """
    auth_token: AuthToken
    refresh_token: Optional[RefreshToken] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert login result to dictionary."""
        result: Dict[str, Any] = {
            'auth_token': self.auth_token.to_dict(),
        }
        if self.refresh_token:
            result['refresh_token'] = self.refresh_token.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LoginResult':
        """Create login result from dictionary."""
        refresh_token = None
        if data.get('refresh_token'):
            refresh_token = RefreshToken.from_dict(data['refresh_token'])

        return cls(
            auth_token=AuthToken.from_dict(data['auth_token']),
            refresh_token=refresh_token,
        )
