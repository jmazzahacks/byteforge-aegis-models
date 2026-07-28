"""Tests for WebhookVerifier."""
import hashlib
import pytest
import hmac
import json
import time
from unittest.mock import patch

from byteforge_aegis_models import WebhookHeaders, WebhookVerifier


class TestWebhookVerifier:
    def setup_method(self) -> None:
        self.verifier = WebhookVerifier()
        self.secret = "test_secret_key_abc123"
        self.timestamp = int(time.time())
        self.payload_dict = {
            "event_type": "user.verified",
            "site_uuid": "0191e1a0-0000-7000-8000-000000000001",
            "user_uuid": "0191e1a0-0000-7000-8000-0000000000aa",
            "email": "test@example.com",
            "aegis_role": "user",
            "timestamp": self.timestamp,
        }
        self.payload_json = json.dumps(self.payload_dict, separators=(",", ":"))
        self.signature = self._compute_sig(self.secret, self.timestamp, self.payload_json)

    def _compute_sig(self, secret: str, timestamp: int, payload_json: str) -> str:
        message = f"{timestamp}.{payload_json}"
        return hmac.new(
            secret.encode(), message.encode(), hashlib.sha256
        ).hexdigest()

    def _make_headers(self) -> dict:
        return {
            "X-Aegis-Signature": f"sha256={self.signature}",
            "X-Aegis-Event": "user.verified",
            "X-Aegis-Timestamp": str(self.timestamp),
        }

    def test_parse_headers(self) -> None:
        raw = self._make_headers()
        parsed = self.verifier.parse_headers(raw)
        assert parsed.signature == f"sha256={self.signature}"
        assert parsed.event_type == "user.verified"
        assert parsed.timestamp == self.timestamp

    def test_parse_headers_case_insensitive(self) -> None:
        raw = {
            "x-aegis-signature": f"sha256={self.signature}",
            "x-aegis-event": "user.verified",
            "x-aegis-timestamp": str(self.timestamp),
        }
        parsed = self.verifier.parse_headers(raw)
        assert parsed.event_type == "user.verified"

    def test_parse_headers_missing_signature(self) -> None:
        raw = {
            "X-Aegis-Event": "user.verified",
            "X-Aegis-Timestamp": str(self.timestamp),
        }
        try:
            self.verifier.parse_headers(raw)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Signature" in str(e)

    def test_parse_headers_invalid_timestamp(self) -> None:
        raw = self._make_headers()
        raw["X-Aegis-Timestamp"] = "not_a_number"
        try:
            self.verifier.parse_headers(raw)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Timestamp" in str(e)

    def test_verify_valid(self) -> None:
        headers = WebhookHeaders(
            signature=f"sha256={self.signature}",
            event_type="user.verified",
            timestamp=self.timestamp,
        )
        assert self.verifier.verify(self.secret, headers, self.payload_json) is True

    def test_verify_wrong_secret(self) -> None:
        headers = WebhookHeaders(
            signature=f"sha256={self.signature}",
            event_type="user.verified",
            timestamp=self.timestamp,
        )
        assert self.verifier.verify("wrong_secret", headers, self.payload_json) is False

    def test_verify_tampered_payload(self) -> None:
        headers = WebhookHeaders(
            signature=f"sha256={self.signature}",
            event_type="user.verified",
            timestamp=self.timestamp,
        )
        tampered = self.payload_json.replace("test@example.com", "hacker@evil.com")
        assert self.verifier.verify(self.secret, headers, tampered) is False

    def test_verify_expired_timestamp(self) -> None:
        old_timestamp = self.timestamp - 600
        old_sig = self._compute_sig(self.secret, old_timestamp, self.payload_json)
        headers = WebhookHeaders(
            signature=f"sha256={old_sig}",
            event_type="user.verified",
            timestamp=old_timestamp,
        )
        assert self.verifier.verify(self.secret, headers, self.payload_json) is False

    def test_verify_future_timestamp(self) -> None:
        future_timestamp = self.timestamp + 600
        future_sig = self._compute_sig(self.secret, future_timestamp, self.payload_json)
        headers = WebhookHeaders(
            signature=f"sha256={future_sig}",
            event_type="user.verified",
            timestamp=future_timestamp,
        )
        assert self.verifier.verify(self.secret, headers, self.payload_json) is False

    def test_verify_payload_convenience(self) -> None:
        raw = self._make_headers()
        result = self.verifier.verify_payload(self.secret, raw, self.payload_json)
        assert result is not None
        assert result.event_type == "user.verified"

    def test_verify_payload_invalid(self) -> None:
        raw = self._make_headers()
        result = self.verifier.verify_payload("wrong", raw, self.payload_json)
        assert result is None

    def test_verify_custom_drift(self) -> None:
        old_timestamp = self.timestamp - 30
        old_sig = self._compute_sig(self.secret, old_timestamp, self.payload_json)
        headers = WebhookHeaders(
            signature=f"sha256={old_sig}",
            event_type="user.verified",
            timestamp=old_timestamp,
        )
        # Within 60s drift - should pass
        assert self.verifier.verify(
            self.secret, headers, self.payload_json, max_drift_seconds=60
        ) is True
        # Within 10s drift - should fail (30s old)
        assert self.verifier.verify(
            self.secret, headers, self.payload_json, max_drift_seconds=10
        ) is False

    def test_swapped_event_header_is_rejected(self) -> None:
        """The replay attack this guard exists for.

        The HMAC covers only "{timestamp}.{body}", so X-Aegis-Event is
        unsigned. A captured user.verified delivery, resent verbatim inside
        the freshness window with the header changed to user.deleted, still
        carries a valid signature — a receiver dispatching on the header
        would delete the account the (signed, unmodified) body names.
        """
        raw = self._make_headers()
        raw["X-Aegis-Event"] = "user.deleted"

        assert self.verifier.verify_payload(self.secret, raw, self.payload_json) is None

        headers = self.verifier.parse_headers(raw)
        assert self.verifier.verify(self.secret, headers, self.payload_json) is False

    def test_matching_event_header_still_passes(self) -> None:
        """The guard must not reject genuine deliveries."""
        raw = self._make_headers()
        assert self.verifier.verify_payload(self.secret, raw, self.payload_json) is not None

    def test_body_without_event_type_is_rejected(self) -> None:
        payload = {k: v for k, v in self.payload_dict.items() if k != "event_type"}
        body = json.dumps(payload, separators=(",", ":"))
        sig = self._compute_sig(self.secret, self.timestamp, body)
        headers = WebhookHeaders(
            signature=f"sha256={sig}",
            event_type="user.verified",
            timestamp=self.timestamp,
        )
        assert self.verifier.verify(self.secret, headers, body) is False

    def test_non_json_body_is_rejected(self) -> None:
        body = "not json at all"
        sig = self._compute_sig(self.secret, self.timestamp, body)
        headers = WebhookHeaders(
            signature=f"sha256={sig}",
            event_type="user.verified",
            timestamp=self.timestamp,
        )
        assert self.verifier.verify(self.secret, headers, body) is False

    def test_non_object_json_body_is_rejected(self) -> None:
        body = json.dumps(["user.verified"])
        sig = self._compute_sig(self.secret, self.timestamp, body)
        headers = WebhookHeaders(
            signature=f"sha256={sig}",
            event_type="user.verified",
            timestamp=self.timestamp,
        )
        assert self.verifier.verify(self.secret, headers, body) is False

    def test_non_ascii_event_header_is_rejected_not_raised(self) -> None:
        """A homoglyph in the unsigned header must fail cleanly.

        hmac.compare_digest raises TypeError on non-ASCII str, and header
        values arrive latin-1-decoded, so comparing them that way turned a
        forged header into a 500 instead of a rejection.
        """
        raw = self._make_headers()
        raw["X-Aegis-Event"] = "user.verifiеd"  # Cyrillic 'е'

        assert self.verifier.verify_payload(self.secret, raw, self.payload_json) is None

    def test_non_ascii_signature_header_is_rejected_not_raised(self) -> None:
        """Unauthenticated callers must not be able to crash a receiver.

        X-Aegis-Signature is attacker-controlled with no capture required;
        a single high byte reaching compare_digest would raise TypeError.
        """
        raw = self._make_headers()
        raw["X-Aegis-Signature"] = "sha256=" + "ÿ" * 64

        assert self.verifier.verify_payload(self.secret, raw, self.payload_json) is None

    def test_malformed_signature_header_is_rejected(self) -> None:
        for bad in ["sha256=", "sha256=xyz", "sha256=" + "a" * 63, "sha256=" + "a" * 65]:
            raw = self._make_headers()
            raw["X-Aegis-Signature"] = bad
            assert self.verifier.verify_payload(self.secret, raw, self.payload_json) is None, bad

    def test_empty_signature_header_raises(self) -> None:
        """An absent header is a caller error, not a failed verification —
        parse_headers documents ValueError for it."""
        raw = self._make_headers()
        raw["X-Aegis-Signature"] = ""
        with pytest.raises(ValueError):
            self.verifier.verify_payload(self.secret, raw, self.payload_json)
