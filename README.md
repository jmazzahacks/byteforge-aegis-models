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
- `WebhookEventType` - Enum for webhook event types (user.verified, user.deleted)
- `WebhookPayload` - Structured webhook payload
- `WebhookEvent` - Webhook delivery log record

## Webhook Verification

The `WebhookVerifier` class verifies HMAC-SHA256 signatures on incoming Aegis webhooks:

```python
import json

from byteforge_aegis_models import WebhookVerifier

verifier = WebhookVerifier()

# Parse and verify in one call
headers = verifier.verify_payload(
    secret="your_webhook_secret",
    raw_headers=request.headers,
    payload_body=request.body,
)

if headers:
    payload = json.loads(request.body)
    # Dispatch on the BODY's event_type, not the header — see below.
    if payload["event_type"] == "user.deleted":
        ...
else:
    print("Invalid signature")
```

### Dispatch on the body, not the `X-Aegis-Event` header

The HMAC covers `"{timestamp}.{raw_body}"` only. The body's `event_type` is signed; **the `X-Aegis-Event` header is not.** A captured delivery replayed inside the freshness window with that header swapped — a `user.verified` turned into a `user.deleted` naming the same user — still carries a valid signature. A receiver that branches on the header would act on the forged type.

As of 2.5.0 `verify()` rejects any delivery whose header disagrees with the body, so a verified delivery has a trustworthy header. Branch on `payload["event_type"]` anyway: it is the signed value, and it cannot be gotten wrong by a later refactor.

## License

[O'Saasy License](https://osaasy.dev/) - Copyright 2026, Really Bad Apps, LLC.
