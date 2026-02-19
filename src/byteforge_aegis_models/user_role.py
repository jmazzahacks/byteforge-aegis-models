"""User role enumeration."""
from enum import Enum


class UserRole(str, Enum):
    """
    User role types.

    Values:
        USER: Regular user with standard permissions
        ADMIN: Site administrator with management permissions
    """
    USER = 'user'
    ADMIN = 'admin'
