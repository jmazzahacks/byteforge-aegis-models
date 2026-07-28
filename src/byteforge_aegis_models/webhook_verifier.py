"""
Webhook signature verification for Aegis webhook receivers.

Mirrors the signing algorithm in the backend's webhook_service.compute_signature().
"""
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


DEFAULT_MAX_DRIFT_SECONDS = 300

# A SHA-256 HMAC rendered as hex. Used to reject malformed signature headers
# before they reach hmac.compare_digest, which raises on non-ASCII input.
_HEX_DIGEST = re.compile(r'[0-9a-fA-F]{64}')


@dataclass
class WebhookHeaders:
    """
    Parsed Aegis webhook headers.

    Attributes:
        signature: The HMAC-SHA256 signature (with 'sha256=' prefix)
        event_type: The event type from the X-Aegis-Event header.

            DO NOT DISPATCH ON THIS. The HMAC covers only
            "{timestamp}.{raw_body}", so this header is NOT signed — the
            body's `event_type` is. An attacker replaying a captured
            delivery within the freshness window can swap this header while
            the signature still verifies. Branch on the parsed body's
            `event_type` instead; treat this as a routing/logging hint.

            `verify()` rejects a delivery whose header disagrees with the
            body, so a verified delivery has a trustworthy header — but code
            that dispatches on the body cannot be gotten wrong by a future
            refactor.
        timestamp: Unix timestamp from the request
    """
    signature: str
    event_type: str
    timestamp: int


class WebhookVerifier:
    """
    Verifies HMAC-SHA256 signatures on incoming Aegis webhooks.

    Usage:
        verifier = WebhookVerifier()
        headers = verifier.parse_headers(request.headers)
        if verifier.verify(secret, headers, request.body):
            payload = json.loads(request.body)
            if payload['event_type'] == 'user.deleted':   # body, not header
                ...
    """

    def parse_headers(self, raw_headers: Dict[str, str]) -> WebhookHeaders:
        """
        Extract Aegis webhook headers from a raw header dict.

        Args:
            raw_headers: Dictionary of HTTP headers (case-insensitive keys supported
                         via common frameworks, but we check exact and lower-case)

        Returns:
            WebhookHeaders with parsed values

        Raises:
            ValueError: If any required header is missing
        """
        signature = self._get_header(raw_headers, 'X-Aegis-Signature')
        event_type = self._get_header(raw_headers, 'X-Aegis-Event')
        timestamp_str = self._get_header(raw_headers, 'X-Aegis-Timestamp')

        if not signature:
            raise ValueError("Missing X-Aegis-Signature header")
        if not event_type:
            raise ValueError("Missing X-Aegis-Event header")
        if not timestamp_str:
            raise ValueError("Missing X-Aegis-Timestamp header")

        try:
            timestamp = int(timestamp_str)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid X-Aegis-Timestamp value: {timestamp_str}")

        return WebhookHeaders(
            signature=signature,
            event_type=event_type,
            timestamp=timestamp,
        )

    def verify(
        self,
        secret: str,
        headers: WebhookHeaders,
        payload_body: str,
        max_drift_seconds: int = DEFAULT_MAX_DRIFT_SECONDS,
    ) -> bool:
        """
        Verify the webhook signature and timestamp freshness.

        Args:
            secret: The site's webhook secret
            headers: Parsed webhook headers
            payload_body: The raw JSON request body as a string
            max_drift_seconds: Maximum allowed age in seconds (default 300)

        Returns:
            True if the signature is valid, the timestamp is fresh, and the
            X-Aegis-Event header agrees with the body's event_type.

        The last check matters: the HMAC covers only "{timestamp}.{body}",
        so the header is unsigned. Without it, a captured delivery could be
        replayed inside the freshness window with the header swapped — e.g.
        a 'user.verified' turned into a 'user.deleted' naming the same user —
        and any receiver dispatching on the header would act on the forged
        type with a signature that checks out.
        """
        now = int(time.time())
        if abs(now - headers.timestamp) > max_drift_seconds:
            return False

        expected_sig = self._compute_signature(secret, headers.timestamp, payload_body)
        actual_sig = headers.signature

        if actual_sig.startswith("sha256="):
            actual_sig = actual_sig[7:]

        # Reject anything that isn't a hex digest before comparing. Header
        # values arrive latin-1-decoded, and hmac.compare_digest raises
        # TypeError on non-ASCII str — so without this an unauthenticated
        # caller could crash any receiver with a single high byte in
        # X-Aegis-Signature.
        if not _HEX_DIGEST.fullmatch(actual_sig):
            return False

        if not hmac.compare_digest(expected_sig, actual_sig):
            return False

        return self._header_matches_body(headers.event_type, payload_body)

    def _header_matches_body(self, header_event_type: str, payload_body: str) -> bool:
        """
        Whether the unsigned X-Aegis-Event header agrees with the signed body.

        A body that isn't JSON, isn't an object, or carries no event_type is
        rejected: every genuine Aegis delivery has all three, so anything
        else is either corruption or tampering.
        """
        try:
            payload = json.loads(payload_body)
        except (ValueError, TypeError):
            return False

        if not isinstance(payload, dict):
            return False

        body_event_type = payload.get('event_type')
        if not isinstance(body_event_type, str):
            return False

        # Plain ==, not compare_digest: neither value is a secret (one is
        # attacker-supplied, the other is public), so constant time buys
        # nothing — and compare_digest raises TypeError on non-ASCII str,
        # which would turn a forged header into a 500 instead of a clean
        # rejection.
        return header_event_type == body_event_type

    def verify_payload(
        self,
        secret: str,
        raw_headers: Dict[str, str],
        payload_body: str,
        max_drift_seconds: int = DEFAULT_MAX_DRIFT_SECONDS,
    ) -> Optional[WebhookHeaders]:
        """
        Convenience method: parse headers and verify in one call.

        Args:
            secret: The site's webhook secret
            raw_headers: Raw HTTP header dictionary
            payload_body: The raw JSON request body as a string
            max_drift_seconds: Maximum allowed age in seconds

        Returns:
            WebhookHeaders if valid, None if verification fails

        Raises:
            ValueError: If required headers are missing
        """
        headers = self.parse_headers(raw_headers)
        if self.verify(secret, headers, payload_body, max_drift_seconds):
            return headers
        return None

    def _compute_signature(self, secret: str, timestamp: int, payload_json: str) -> str:
        """
        Compute HMAC-SHA256 signature matching the backend algorithm.

        Message format: "{timestamp}.{payload_json}"
        where payload_json uses compact separators (',', ':').
        """
        message = f"{timestamp}.{payload_json}"
        return hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _get_header(self, headers: Dict[str, str], name: str) -> Optional[str]:
        """Get a header value, checking both exact case and lower-case."""
        if name in headers:
            return headers[name]
        lower_name = name.lower()
        for key, value in headers.items():
            if key.lower() == lower_name:
                return value
        return None
