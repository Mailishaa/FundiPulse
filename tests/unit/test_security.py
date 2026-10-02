"""Unit tests for the pure security primitives.

No database and no HTTP: these exercise Argon2 hashing, password policy, opaque
token generation and JWT issue/verify in isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import time
import uuid

import jwt
import pytest

from app.core.config import Settings, get_settings
from app.core.constants import TokenPurpose
from app.core.exceptions import (
    InvalidTokenError,
    PasswordPolicyError,
    TokenExpiredError,
    ValidationError,
)
from app.core.security import (
    PasswordHasherService,
    TokenService,
    check_password_policy,
    constant_time_compare,
    enforce_password_policy,
    generate_opaque_token,
    hash_opaque_token,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def hasher() -> PasswordHasherService:
    return PasswordHasherService(get_settings())


@pytest.fixture
def token_service() -> TokenService:
    return TokenService(get_settings())


# --------------------------------------------------------------------------- #
# Password hashing                                                            #
# --------------------------------------------------------------------------- #
class TestPasswordHashing:
    def test_hash_is_argon2id_and_never_the_password(self, hasher: PasswordHasherService) -> None:
        password = "Correct-Horse-9-Battery"
        digest = hasher.hash(password)

        assert digest.startswith("$argon2id$")
        assert password not in digest
        assert "Correct-Horse" not in digest

    def test_verify_accepts_the_correct_password(self, hasher: PasswordHasherService) -> None:
        digest = hasher.hash("Correct-Horse-9-Battery")
        assert hasher.verify("Correct-Horse-9-Battery", digest) is True

    def test_verify_rejects_a_wrong_password(self, hasher: PasswordHasherService) -> None:
        digest = hasher.hash("Correct-Horse-9-Battery")
        assert hasher.verify("Correct-Horse-9-Batterz", digest) is False

    def test_verify_returns_false_for_a_malformed_hash(self, hasher: PasswordHasherService) -> None:
        """A corrupt stored hash must not raise - that would be a 500 that tells
        an attacker the account exists."""
        assert hasher.verify("anything", "not-a-hash") is False
        assert hasher.verify("anything", "") is False

    def test_hashes_are_salted_so_identical_passwords_differ(
        self, hasher: PasswordHasherService
    ) -> None:
        first = hasher.hash("Correct-Horse-9-Battery")
        second = hasher.hash("Correct-Horse-9-Battery")
        assert first != second

    def test_needs_rehash_is_false_for_current_parameters(
        self, hasher: PasswordHasherService
    ) -> None:
        assert hasher.needs_rehash(hasher.hash("whatever12")) is False

    def test_needs_rehash_is_true_for_an_unparsable_hash(
        self, hasher: PasswordHasherService
    ) -> None:
        assert hasher.needs_rehash("garbage") is True

    def test_test_suite_never_uses_weaker_hashing_than_production(self) -> None:
        """Guard against the test speed-up leaking into production defaults.

        Reads the *declared defaults* rather than constructing a Settings
        instance, because constructing one would pick up the deliberately cheap
        Argon2 values this test session sets in the environment.
        """
        defaults = Settings.model_fields
        assert defaults["argon2_memory_cost"].default >= 65536, (
            "production memory cost must default to >= 64 MiB"
        )
        assert defaults["argon2_time_cost"].default >= 3, (
            "production time cost must default to >= 3"
        )
        assert defaults["argon2_parallelism"].default >= 4, (
            "production parallelism must default to >= 4"
        )


# --------------------------------------------------------------------------- #
# Password policy                                                             #
# --------------------------------------------------------------------------- #
class TestPasswordPolicy:
    @pytest.mark.parametrize(
        "password",
        [
            "Correct-Horse-9-Battery",
            "a-very-long-passphrase-with-many-words",
            "Mwangaza2026!",
            "siteforeman123",
        ],
    )
    def test_accepts_reasonable_passwords(self, password: str) -> None:
        assert check_password_policy(password).ok is True

    @pytest.mark.parametrize(
        "password",
        ["short1", "12345678", "abc", "a" * 200],
    )
    def test_rejects_short_or_long_passwords(self, password: str) -> None:
        assert check_password_policy(password).ok is False

    def test_rejects_a_common_password(self) -> None:
        result = check_password_policy("password123")
        assert result.ok is False
        assert any("common" in failure for failure in result.failures)

    def test_reports_every_failure_not_just_the_first(self) -> None:
        """A user filling in a form should not have to guess one rule at a time."""
        # Short *and* contains neither a letter nor a digit: two distinct rules.
        result = check_password_policy("!@#$%")
        assert len(result.failures) >= 2, result.failures

    def test_enforce_raises_with_an_actionable_message(self) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            enforce_password_policy("short")
        assert "characters" in str(excinfo.value)

    def test_enforce_strips_surrounding_whitespace(self) -> None:
        """A paste with a trailing newline is a common cause of a spurious failure."""
        enforce_password_policy("  Correct-Horse-9-Battery  ")

    def test_enforce_raises_on_a_very_long_password(self) -> None:
        """Caps Argon2 cost on an adversarial input."""
        with pytest.raises(PasswordPolicyError):
            enforce_password_policy("a" * 10_000)


# --------------------------------------------------------------------------- #
# Opaque tokens                                                              #
# --------------------------------------------------------------------------- #
class TestOpaqueTokens:
    def test_tokens_are_unique_and_long_enough(self) -> None:
        tokens = {generate_opaque_token() for _ in range(500)}
        assert len(tokens) == 500
        assert all(len(token) >= 32 for token in tokens)

    def test_hashing_is_deterministic_so_lookup_works(self) -> None:
        token = generate_opaque_token()
        assert hash_opaque_token(token) == hash_opaque_token(token)

    def test_hashing_does_not_recover_the_token(self) -> None:
        token = generate_opaque_token()
        assert token not in hash_opaque_token(token)

    def test_hash_is_domain_separated_from_other_digests(self) -> None:
        """A token digest must not be usable as any other kind of digest."""
        import hashlib

        token = generate_opaque_token()
        assert hash_opaque_token(token) != hashlib.sha256(token.encode()).hexdigest()

    def test_different_tokens_hash_differently(self) -> None:
        assert hash_opaque_token("token-a") != hash_opaque_token("token-b")

    def test_refuses_an_absurdly_short_token(self) -> None:
        with pytest.raises(ValueError):
            generate_opaque_token(8)

    def test_constant_time_compare(self) -> None:
        assert constant_time_compare("abc", "abc") is True
        assert constant_time_compare("abc", "abd") is False
        assert constant_time_compare("abc", "abcd") is False


# --------------------------------------------------------------------------- #
# Access tokens                                                              #
# --------------------------------------------------------------------------- #
class TestAccessTokens:
    def test_round_trips_claims(self, token_service: TokenService) -> None:
        subject = uuid.uuid4()
        issued = token_service.create_access_token(subject=subject, role="WORKER")
        claims = token_service.decode_access_token(issued.token)

        assert claims.subject == subject
        assert claims.role == "WORKER"
        assert claims.token_id == issued.token_id
        assert claims.is_expired is False

    def test_expires_within_the_configured_lifetime(self, token_service: TokenService) -> None:
        issued = token_service.create_access_token(subject=uuid.uuid4(), role="WORKER")
        ttl = issued.expires_at - datetime.now(UTC)
        assert timedelta(minutes=14) < ttl <= timedelta(minutes=15)

    def test_rejects_an_expired_token(self, token_service: TokenService) -> None:
        issued = token_service.create_access_token(
            subject=uuid.uuid4(), role="WORKER", lifetime=timedelta(seconds=-1)
        )
        with pytest.raises(TokenExpiredError):
            token_service.decode_access_token(issued.token)

    def test_rejects_a_token_signed_with_a_different_secret(
        self, token_service: TokenService
    ) -> None:
        other = TokenService(
            Settings(
                _env_file=None,  # type: ignore[call-arg]
                secret_key="a" * 40,
                jwt_secret="b" * 40,
            )
        )
        issued = other.create_access_token(subject=uuid.uuid4(), role="WORKER")
        with pytest.raises(InvalidTokenError):
            token_service.decode_access_token(issued.token)

    def test_rejects_an_unsigned_alg_none_token(self, token_service: TokenService) -> None:
        """The classic JWT downgrade: strip the signature and set alg=none."""
        now = datetime.now(UTC)
        forged = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "iss": get_settings().jwt_issuer,
                "aud": get_settings().jwt_audience,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
                "jti": str(uuid.uuid4()),
                "typ": "access",
                "role": "ADMIN",
            },
            key="",
            algorithm="none",
        )
        with pytest.raises(InvalidTokenError):
            token_service.decode_access_token(forged)

    def test_rejects_a_token_with_the_wrong_audience(self, token_service: TokenService) -> None:
        now = datetime.now(UTC)
        forged = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "iss": get_settings().jwt_issuer,
                "aud": "some-other-api",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
                "jti": str(uuid.uuid4()),
                "typ": "access",
            },
            get_settings().jwt_secret.get_secret_value(),
            algorithm=get_settings().jwt_algorithm,
        )
        with pytest.raises(InvalidTokenError):
            token_service.decode_access_token(forged)

    def test_rejects_a_token_with_the_wrong_issuer(self, token_service: TokenService) -> None:
        now = datetime.now(UTC)
        forged = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "iss": "some-other-issuer",
                "aud": get_settings().jwt_audience,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
                "jti": str(uuid.uuid4()),
                "typ": "access",
            },
            get_settings().jwt_secret.get_secret_value(),
            algorithm=get_settings().jwt_algorithm,
        )
        with pytest.raises(InvalidTokenError):
            token_service.decode_access_token(forged)

    def test_rejects_a_token_missing_required_claims(self, token_service: TokenService) -> None:
        now = datetime.now(UTC)
        incomplete = jwt.encode(
            {"sub": str(uuid.uuid4()), "exp": int((now + timedelta(hours=1)).timestamp())},
            get_settings().jwt_secret.get_secret_value(),
            algorithm=get_settings().jwt_algorithm,
        )
        with pytest.raises(InvalidTokenError):
            token_service.decode_access_token(incomplete)

    def test_rejects_a_token_of_the_wrong_type(self, token_service: TokenService) -> None:
        """A token minted for another purpose must not authenticate."""
        settings = get_settings()
        now = datetime.now(UTC)
        wrong_type = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "iss": settings.jwt_issuer,
                "aud": settings.jwt_audience,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
                "jti": str(uuid.uuid4()),
                "typ": "invitation",
            },
            settings.jwt_secret.get_secret_value(),
            algorithm=settings.jwt_algorithm,
        )
        with pytest.raises(InvalidTokenError):
            token_service.decode_access_token(wrong_type)

    @pytest.mark.parametrize("garbage", ["", "not-a-token", "a.b.c", "....", "null"])
    def test_rejects_structurally_invalid_tokens(
        self, token_service: TokenService, garbage: str
    ) -> None:
        with pytest.raises(InvalidTokenError):
            token_service.decode_access_token(garbage)

    def test_two_issues_of_the_same_subject_get_distinct_ids(
        self, token_service: TokenService
    ) -> None:
        """Distinct jti keeps revocation and correlation meaningful."""
        subject = uuid.uuid4()
        first = token_service.create_access_token(subject=subject, role="WORKER")
        second = token_service.create_access_token(subject=subject, role="WORKER")
        assert first.token_id != second.token_id
        assert first.token != second.token


class TestTokenLifetimes:
    def test_refresh_lifetime_matches_configuration(self) -> None:
        settings = get_settings()
        assert TokenService.refresh_token_lifetime(settings) == timedelta(
            days=settings.refresh_token_expire_days
        )

    def test_absolute_family_ceiling_is_longer_than_one_refresh(self) -> None:
        """Rotation must not be able to extend a session forever."""
        settings = get_settings()
        assert TokenService.refresh_family_lifetime(
            settings
        ) >= TokenService.refresh_token_lifetime(settings)


class TestEmailNormalisation:
    def test_lowercases_the_address(self) -> None:
        from app.utils.email import normalise_email

        assert normalise_email("  Worker@Example.COM  ") == "worker@example.com"

    @pytest.mark.parametrize(
        "invalid",
        [
            "",
            "   ",
            "not-an-email",
            "@example.com",
            "user@",
            "user@@example.com",
            "a b@example.com",
        ],
    )
    def test_rejects_malformed_addresses_with_one_generic_message(self, invalid: str) -> None:
        """A generic message avoids being a validation oracle."""
        from app.utils.email import normalise_email

        with pytest.raises(ValidationError) as excinfo:
            normalise_email(invalid)
        assert str(excinfo.value) == "A valid email address is required."

    def test_masking_hides_the_local_part(self) -> None:
        from app.utils.email import mask_email

        masked = mask_email("construction.worker@example.com")
        assert "construction" not in masked
        assert masked.endswith("m")


class TestTokenPurposeNamespace:
    def test_purposes_are_distinct(self) -> None:
        """Reset and verification tokens must not be interchangeable."""
        assert TokenPurpose.PASSWORD_RESET != TokenPurpose.EMAIL_VERIFICATION
        assert TokenPurpose.PASSWORD_RESET.value != TokenPurpose.EMAIL_VERIFICATION.value


class TestHashingPerformance:
    def test_verification_is_deliberately_slow(self, hasher: PasswordHasherService) -> None:
        """Sanity check that Argon2's cost is actually being applied.

        Not a benchmark - just a guard against a silent switch to a fast hash.
        """
        digest = hasher.hash("Correct-Horse-9-Battery")
        started = time.perf_counter()
        hasher.verify("Correct-Horse-9-Battery", digest)
        elapsed = time.perf_counter() - started
        assert elapsed > 0.0005, "hashing appears to have become trivial"
