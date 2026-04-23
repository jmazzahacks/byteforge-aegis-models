# byteforge-aegis-models

Shared Python models for the [ByteForge Aegis](https://github.com/jmazzahacks/byteforge-aegis) multi-tenant authentication service.

## Installation

```bash
pip install git+https://github.com/jmazzahacks/byteforge-aegis-models.git
```

## Models

- `UserRole` - Enum for user roles (user, admin)
- `Site` - Tenant site configuration
- `User` - User account (excludes password_hash)
- `AuthToken` - Short-lived authentication token
- `RefreshToken` - Long-lived refresh token
- `LoginResult` - Composite login/refresh response
- `VerificationResult` - Email verification result
- `VerificationTokenStatus` - Token check response
- `WebhookPayload` - Structured webhook payload
- `WebhookEvent` - Webhook delivery log record

## Webhook Verification

The `WebhookVerifier` class verifies HMAC-SHA256 signatures on incoming Aegis webhooks:

```python
from byteforge_aegis_models import WebhookVerifier

verifier = WebhookVerifier()

# Parse and verify in one call
headers = verifier.verify_payload(
    secret="your_webhook_secret",
    raw_headers=request.headers,
    payload_body=request.body,
)

if headers:
    print(f"Valid webhook: {headers.event_type}")
else:
    print("Invalid signature")
```

## License

[O'Saasy License](https://osaasy.dev/) - Copyright 2026, Really Bad Apps, LLC.
