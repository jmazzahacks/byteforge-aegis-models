from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class Site:
    """
    Site model representing a registered website/application (tenant).

    Each site is a separate tenant in the multi-tenant architecture.
    Users are scoped to a specific site.

    Attributes:
        id: Legacy integer site identifier (read-only during the UUID
            migration; will be removed once all tenants migrate to uuid)
        uuid: Globally-unique site identifier (UUIDv7). Source of truth.
        name: Human-readable name of the site
        domain: Domain name of the site (unique)
        frontend_url: Frontend URL for this site (used in email links)
        email_from: Email address to send emails from for this site
        email_from_name: Display name for emails sent from this site
        created_at: Unix timestamp when the site was created
        updated_at: Unix timestamp when the site was last updated
        verification_redirect_url: URL to redirect to after email verification
        allow_self_registration: Whether public self-registration is enabled
        webhook_url: URL to receive webhook notifications
        webhook_secret: HMAC secret for webhook signature verification
        tenant_api_key: Per-tenant secret required in X-Tenant-Api-Key header
            on public auth endpoints (register, login, password reset, etc.).
            Must live server-side on the tenant's backend.
        mailgun_domain: Mailgun sending domain for this site (e.g.
            "mg.tenantcorp.com"). When set, emails for this site route through
            this domain. When null, falls back to the global MAILGUN_DOMAIN.
        mailgun_api_key: Mailgun API key for this site. When set, used to
            authenticate sends through the per-site domain. When null, falls
            back to the global MAILGUN_API_KEY.
    """
    id: int
    name: str
    domain: str
    frontend_url: str
    email_from: str
    email_from_name: str
    created_at: int
    updated_at: int
    uuid: Optional[str] = None
    verification_redirect_url: Optional[str] = None
    allow_self_registration: bool = True
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    tenant_api_key: Optional[str] = None
    mailgun_domain: Optional[str] = None
    mailgun_api_key: Optional[str] = None

    def get_verification_redirect_url(self) -> str:
        """Get the URL to redirect to after email verification."""
        return self.verification_redirect_url or self.frontend_url

    def to_dict(self) -> Dict[str, Any]:
        """Convert site model to dictionary."""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'name': self.name,
            'domain': self.domain,
            'frontend_url': self.frontend_url,
            'verification_redirect_url': self.verification_redirect_url,
            'email_from': self.email_from,
            'email_from_name': self.email_from_name,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'allow_self_registration': self.allow_self_registration,
            'webhook_url': self.webhook_url,
            'mailgun_domain': self.mailgun_domain,
        }

    def to_admin_dict(self) -> Dict[str, Any]:
        """Convert site model to dictionary including secrets (admin-only use)."""
        result = self.to_dict()
        result['webhook_secret'] = self.webhook_secret
        result['tenant_api_key'] = self.tenant_api_key
        result['mailgun_api_key'] = self.mailgun_api_key
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Site':
        """Create site model from dictionary."""
        return cls(
            id=data['id'],
            uuid=data.get('uuid'),
            name=data['name'],
            domain=data['domain'],
            frontend_url=data['frontend_url'],
            verification_redirect_url=data.get('verification_redirect_url'),
            email_from=data['email_from'],
            email_from_name=data['email_from_name'],
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            allow_self_registration=data.get('allow_self_registration', True),
            webhook_url=data.get('webhook_url'),
            webhook_secret=data.get('webhook_secret'),
            tenant_api_key=data.get('tenant_api_key'),
            mailgun_domain=data.get('mailgun_domain'),
            mailgun_api_key=data.get('mailgun_api_key'),
        )
