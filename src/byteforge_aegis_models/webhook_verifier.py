"""
Webhook signature verification for Aegis webhook receivers.

Mirrors the signing algorithm in the backend's webhook_service.compute_signature().
"""
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


DEFAULT_MAX_DRIFT_SECONDS = 300


@dataclass
class WebhookHeaders:
    """
    Parsed Aegis webhook headers.

    Attributes:
        signature: The HMAC-SHA256 signature (with 'sha256=' prefix)
        event_type: The event type (e.g., 'user.verified')
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
            # process webhook
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
            True if signature is valid and timestamp is fresh
        """
        now = int(time.time())
        if abs(now - headers.timestamp) > max_drift_seconds:
            return False

        expected_sig = self._compute_signature(secret, headers.timestamp, payload_body)
        actual_sig = headers.signature

        if actual_sig.startswith("sha256="):
            actual_sig = actual_sig[7:]

        return hmac.compare_digest(expected_sig, actual_sig)

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
