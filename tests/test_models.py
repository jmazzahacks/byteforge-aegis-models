"""Tests for all byteforge-aegis-models dataclasses."""
from byteforge_aegis_models import (
    AuthToken,
    LoginResult,
    RefreshToken,
    Site,
    User,
    UserRole,
    VerificationResult,
    VerificationTokenStatus,
    WebhookEvent,
    WebhookEventType,
    WebhookPayload,
)

SITE_UUID = "0191e1a0-0000-7000-8000-000000000001"
USER_UUID = "0191e1a0-0000-7000-8000-0000000000aa"
EVENT_UUID = "0191e1a0-0000-7000-8000-0000000000ee"


class TestUserRole:
    def test_values(self) -> None:
        assert UserRole.USER.value == "user"
        assert UserRole.ADMIN.value == "admin"

    def test_from_string(self) -> None:
        assert UserRole("user") == UserRole.USER
        assert UserRole("admin") == UserRole.ADMIN


class TestSite:
    def _make_site(self) -> Site:
        return Site(
            uuid=SITE_UUID,
            name="Test Site",
            domain="test.example.com",
            frontend_url="https://test.example.com",
            email_from="noreply@test.example.com",
            email_from_name="Test Site",
            created_at=1700000000,
            updated_at=1700000100,
            verification_redirect_url="https://test.example.com/welcome",
            webhook_url="https://test.example.com/webhook",
            webhook_secret="abc123",
        )

    def test_to_dict(self) -> None:
        site = self._make_site()
        d = site.to_dict()
        assert d["uuid"] == SITE_UUID
        assert d["name"] == "Test Site"
        assert d["domain"] == "test.example.com"
        assert d["webhook_url"] == "https://test.example.com/webhook"
        # webhook_secret is intentionally excluded from to_dict
        assert "webhook_secret" not in d
        # The legacy integer id is gone as of 2.0.0.
        assert "id" not in d

    def test_from_dict_roundtrip(self) -> None:
        site = self._make_site()
        d = site.to_dict()
        d["webhook_secret"] = "abc123"
        restored = Site.from_dict(d)
        assert restored.uuid == site.uuid
        assert restored.webhook_secret == "abc123"

    def test_get_verification_redirect_url_with_override(self) -> None:
        site = self._make_site()
        assert site.get_verification_redirect_url() == "https://test.example.com/welcome"

    def test_get_verification_redirect_url_fallback(self) -> None:
        site = self._make_site()
        site.verification_redirect_url = None
        assert site.get_verification_redirect_url() == "https://test.example.com"

    def test_defaults(self) -> None:
        site = Site(
            uuid=SITE_UUID, name="Min", domain="min.com",
            frontend_url="https://min.com", email_from="a@b.com",
            email_from_name="Min", created_at=0, updated_at=0,
        )
        assert site.allow_self_registration is True
        assert site.webhook_url is None
        assert site.webhook_secret is None
        assert site.verification_redirect_url is None


class TestUser:
    def _make_user(self) -> User:
        return User(
            uuid=USER_UUID,
            site_uuid=SITE_UUID,
            email="user@test.com",
            is_verified=True,
            role=UserRole.USER,
            created_at=1700000000,
            updated_at=1700000100,
        )

    def test_to_dict(self) -> None:
        user = self._make_user()
        d = user.to_dict()
        assert d["uuid"] == USER_UUID
        assert d["site_uuid"] == SITE_UUID
        assert d["role"] == "user"
        assert "password_hash" not in d
        assert "id" not in d
        assert "site_id" not in d

    def test_from_dict_roundtrip(self) -> None:
        user = self._make_user()
        restored = User.from_dict(user.to_dict())
        assert restored == user

    def test_admin_role(self) -> None:
        user = self._make_user()
        user.role = UserRole.ADMIN
        assert user.to_dict()["role"] == "admin"


class TestAuthToken:
    def test_minimal(self) -> None:
        token = AuthToken(token="tok_abc", user_uuid=USER_UUID, expires_at=1700009999)
        assert token.site_uuid is None
        assert token.created_at is None

    def test_to_dict_excludes_none(self) -> None:
        token = AuthToken(token="tok_abc", user_uuid=USER_UUID, expires_at=1700009999)
        d = token.to_dict()
        assert "site_uuid" not in d
        assert "created_at" not in d

    def test_to_dict_includes_when_present(self) -> None:
        token = AuthToken(token="tok_abc", user_uuid=USER_UUID, expires_at=1700009999,
                          site_uuid=SITE_UUID, created_at=1700000000)
        d = token.to_dict()
        assert d["site_uuid"] == SITE_UUID
        assert d["created_at"] == 1700000000

    def test_from_dict_roundtrip(self) -> None:
        token = AuthToken(token="tok_abc", user_uuid=USER_UUID, expires_at=1700009999,
                          site_uuid=SITE_UUID, created_at=1700000000)
        restored = AuthToken.from_dict(token.to_dict())
        assert restored == token

    def test_to_dict_has_no_int_ids(self) -> None:
        token = AuthToken(token="tok_abc", user_uuid=USER_UUID, expires_at=1700009999,
                          site_uuid=SITE_UUID, created_at=1700000000)
        d = token.to_dict()
        assert "user_id" not in d
        assert "site_id" not in d


class TestRefreshToken:
    def _make_token(self) -> RefreshToken:
        return RefreshToken(
            token="ref_abc", site_uuid=SITE_UUID, user_uuid=USER_UUID,
            family_id="fam_123", expires_at=1700099999, created_at=1700000000,
        )

    def test_defaults(self) -> None:
        token = self._make_token()
        assert token.used_at is None
        assert token.revoked is False

    def test_from_dict_roundtrip(self) -> None:
        token = self._make_token()
        token.used_at = 1700050000
        token.revoked = True
        restored = RefreshToken.from_dict(token.to_dict())
        assert restored == token

    def test_from_api_wire_format(self) -> None:
        """API responses (per RefreshTokenResponseSchema) omit family_id,
        created_at, used_at, and revoked. from_dict must accept this shape."""
        wire = {
            "token": "ref_abc",
            "site_uuid": SITE_UUID,
            "user_uuid": USER_UUID,
            "expires_at": 1700099999,
        }
        token = RefreshToken.from_dict(wire)
        assert token.token == "ref_abc"
        assert token.site_uuid == SITE_UUID
        assert token.user_uuid == USER_UUID
        assert token.expires_at == 1700099999
        assert token.family_id is None
        assert token.created_at is None
        assert token.used_at is None
        assert token.revoked is False

    def test_to_dict_has_no_int_ids(self) -> None:
        d = self._make_token().to_dict()
        assert "user_id" not in d
        assert "site_id" not in d


class TestLoginResult:
    def test_with_refresh_token(self) -> None:
        result = LoginResult(
            auth_token=AuthToken(token="a", user_uuid=USER_UUID, expires_at=9999),
            refresh_token=RefreshToken(
                token="r", site_uuid=SITE_UUID, user_uuid=USER_UUID,
                family_id="f", expires_at=99999, created_at=0,
            ),
        )
        d = result.to_dict()
        assert "auth_token" in d
        assert "refresh_token" in d
        restored = LoginResult.from_dict(d)
        assert restored.auth_token.token == "a"
        assert restored.refresh_token is not None
        assert restored.refresh_token.token == "r"

    def test_without_refresh_token(self) -> None:
        result = LoginResult(
            auth_token=AuthToken(token="a", user_uuid=USER_UUID, expires_at=9999),
        )
        d = result.to_dict()
        assert "refresh_token" not in d
        restored = LoginResult.from_dict(d)
        assert restored.refresh_token is None


class TestVerificationResult:
    def test_roundtrip(self) -> None:
        user = User(uuid=USER_UUID, site_uuid=SITE_UUID, email="a@b.com",
                    is_verified=True, role=UserRole.USER, created_at=0, updated_at=0)
        result = VerificationResult(user=user, redirect_url="https://example.com/welcome")
        restored = VerificationResult.from_dict(result.to_dict())
        assert restored.user.email == "a@b.com"
        assert restored.redirect_url == "https://example.com/welcome"


class TestVerificationTokenStatus:
    def test_roundtrip(self) -> None:
        status = VerificationTokenStatus(password_required=True, email="a@b.com")
        restored = VerificationTokenStatus.from_dict(status.to_dict())
        assert restored == status


class TestWebhookPayload:
    def _make_payload(self) -> WebhookPayload:
        return WebhookPayload(
            event_type=WebhookEventType.USER_VERIFIED, site_uuid=SITE_UUID, user_uuid=USER_UUID,
            email="a@b.com", aegis_role="user", timestamp=1700000000,
        )

    def test_to_dict(self) -> None:
        d = self._make_payload().to_dict()
        assert d["event_type"] == "user.verified"
        assert isinstance(d["event_type"], str) and not isinstance(d["event_type"], WebhookEventType)
        assert d["site_uuid"] == SITE_UUID
        assert d["user_uuid"] == USER_UUID
        assert "site_id" not in d
        assert "user_id" not in d

    def test_from_dict_roundtrip(self) -> None:
        payload = self._make_payload()
        d = payload.to_dict()
        assert WebhookPayload.from_dict(d) == payload
        # Wire format roundtrips to the exact same dict.
        assert WebhookPayload.from_dict(d).to_dict() == d

    def test_from_dict_unknown_event_type_rejected(self) -> None:
        d = self._make_payload().to_dict()
        d["event_type"] = "user.exploded"
        try:
            WebhookPayload.from_dict(d)
            assert False, "expected ValueError for unknown event_type"
        except ValueError:
            pass


class TestWebhookEventType:
    def test_values(self) -> None:
        assert WebhookEventType.USER_VERIFIED.value == "user.verified"
        assert WebhookEventType.USER_DELETED.value == "user.deleted"

    def test_compares_equal_to_plain_string(self) -> None:
        # Tenants compare against raw strings; the str-subclass enum must match.
        assert WebhookEventType.USER_DELETED == "user.deleted"


class TestWebhookEvent:
    def test_roundtrip(self) -> None:
        event = WebhookEvent(
            uuid=EVENT_UUID, site_uuid=SITE_UUID, event_type="user.verified",
            payload='{"test": true}', response_status=200,
            response_body="OK", success=True, created_at=1700000000,
        )
        restored = WebhookEvent.from_dict(event.to_dict())
        assert restored == event

    def test_optional_fields(self) -> None:
        event = WebhookEvent(
            uuid=EVENT_UUID, site_uuid=SITE_UUID, event_type="user.verified",
            payload='{}', response_status=None,
            response_body=None, success=False, created_at=0,
        )
        assert event.response_status is None
        d = event.to_dict()
        assert "id" not in d
        assert "site_id" not in d
