"""Cryptographic primitives: password hashing, JWTs, and opaque tokens.

Three separate concerns live here because they share one principle: **nothing
secret is ever stored, and nothing secret is ever logged.**

Passwords
    Argon2id via ``argon2-cffi`` directly. ``passlib`` is deliberately not used:
    it is unmaintained and its Argon2 backend lags the reference
    implementation, which is precisely the primitive where a lag matters.

Access tokens
    HS256 JWT with ``iss``, ``aud``, ``sub``, ``iat``, ``exp`` and ``jti``,
    all validated on every request. The algorithm is pinned from configuration
    rather than read from the token header, so an attacker cannot downgrade to
    ``alg: none`` or to an asymmetric algorithm the service does not intend.

Refresh, reset, invitation tokens
    Opaque 256-bit random values. Only a SHA-256 hash is persisted, so a database
    disclosure yields no usable credential. The plaintext exists once, at issue
    time, and is returned to the caller for delivery.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import secrets
from typing import Any, Final
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    InvalidTokenError,
    PasswordPolicyError,
    TokenExpiredError,
)

#: Length in bytes of every opaque token. 32 bytes = 256 bits, which makes the
#: token space non-guessable rather than merely long.
OPAQUE_TOKEN_BYTES: Final[int] = 32

#: Salt/pepper applied when hashing opaque tokens. Purpose-separated from any
#: other hash in the system so a token hash can never collide with, or be
#: confused for, a password hash.
_TOKEN_HASH_DOMAIN: Final[bytes] = b"fundipulse:token:v1:"


# --------------------------------------------------------------------------- #
# Password hashing                                                            #
# --------------------------------------------------------------------------- #
class PasswordHasherService:
    """Argon2id password hashing, configured from environment settings.

    Parameters come from configuration rather than being hardcoded so that an
    operator can raise the cost on a real deployment, and so the test suite can
    lower it to keep the suite fast without weakening production.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._hasher = PasswordHasher(
            time_cost=self._settings.argon2_time_cost,
            memory_cost=self._settings.argon2_memory_cost,
            parallelism=self._settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
        )

    def hash(self, password: str) -> str:
        """Return an Argon2id hash. Never log, return in a response, or store
        anywhere but ``users.password_hash``."""
        return self._hasher.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        """Verify a password against a stored hash.

        Returns ``False`` rather than raising for any failure, including a
        malformed stored hash, so a corrupt row cannot produce a 500 that tells
        an attacker the account exists.
        """
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        """Whether a stored hash uses weaker parameters than currently configured.

        Lets the cost be raised without forcing a mass password reset: each user
        is upgraded transparently the next time they log in successfully.
        """
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            # A hash we cannot parse is not a hash we should keep trusting.
            return True


# --------------------------------------------------------------------------- #
# Opaque tokens                                                              #
# --------------------------------------------------------------------------- #
def generate_opaque_token(nbytes: int = OPAQUE_TOKEN_BYTES) -> str:
    """Return a URL-safe, cryptographically random token.

    ``secrets.token_urlsafe`` uses a CSPRNG; this is not replaceable with
    ``random`` or with a UUID, both of which are predictable.
    """
    if nbytes < 16:
        raise ValueError("opaque tokens must be at least 16 bytes")
    return secrets.token_urlsafe(nbytes)


def hash_opaque_token(token: str) -> str:
    """Return the storable digest of an opaque token.

    Domain-separated with a constant prefix so a token digest cannot be confused
    with any other digest in the system. SHA-256 (not Argon2) is correct here:
    the input already has 256 bits of entropy, so there is nothing for a slow
    hash to brute-force, and lookups must stay indexed and fast.
    """
    return hashlib.sha256(_TOKEN_HASH_DOMAIN + token.encode("utf-8")).hexdigest()


def constant_time_compare(left: str, right: str) -> bool:
    """Timing-safe string comparison."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Access tokens (JWT)                                                         #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """The validated claim set of an access token."""

    subject: uuid.UUID
    token_id: uuid.UUID
    issued_at: datetime
    expires_at: datetime
    role: str
    session_id: uuid.UUID | None = None

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    token: str
    expires_at: datetime
    token_id: uuid.UUID


class TokenService:
    """Issues and validates short-lived access tokens.

    Validation is deliberately strict. A JWT library will happily accept a token
    whose ``alg`` differs from the expected one unless told otherwise, and will
    accept an unsigned token unless the algorithm is pinned. Both are classic
    JWT attacks, so the expected algorithm, issuer and audience all come from
    configuration and are checked on every verification.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    # -- issuing --------------------------------------------------------- #

    def create_access_token(
        self,
        *,
        subject: uuid.UUID,
        role: str,
        session_id: uuid.UUID | None = None,
        lifetime: timedelta | None = None,
    ) -> IssuedAccessToken:
        """Mint an access token.

        A short lifetime (15 minutes by default) is the primary containment
        control: it bounds how long a stolen token is useful, and keeps the
        blast radius small without needing to check a revocation list on every
        request.
        """
        now = datetime.now(UTC)
        ttl = lifetime or timedelta(minutes=self._settings.access_token_expire_minutes)
        expires_at = now + ttl
        token_id = uuid.uuid4()

        claims: dict[str, Any] = {
            "sub": str(subject),
            "iss": self._settings.jwt_issuer,
            "aud": self._settings.jwt_audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(token_id),
            "typ": "access",
            "role": role,
        }
        if session_id is not None:
            claims["sid"] = str(session_id)

        token = jwt.encode(
            claims,
            self._settings.jwt_secret.get_secret_value(),
            algorithm=self._settings.jwt_algorithm,
        )
        return IssuedAccessToken(token=token, expires_at=expires_at, token_id=token_id)

    # -- verifying ------------------------------------------------------- #

    def decode_access_token(self, token: str) -> AccessTokenClaims:
        """Validate a token and return its claims.

        Raises :class:`TokenExpiredError` or :class:`InvalidTokenError`. The
        distinction is deliberate: a client needs to know to refresh rather than
        to re-authenticate. Neither error reveals anything about other accounts.
        """
        settings = self._settings
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret.get_secret_value(),
                algorithms=[settings.jwt_algorithm],
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                options={
                    "require": ["exp", "iat", "sub", "jti", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    # Without this, a token with no `nbf` would be accepted and
                    # future-dated tokens would be silently tolerated.
                    "verify_nbf": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError() from exc
        except jwt.InvalidTokenError as exc:
            # Covers bad signature, wrong algorithm, wrong issuer/audience,
            # missing claims and malformed structure. All are reported
            # identically so the error cannot be used as an oracle.
            raise InvalidTokenError() from exc

        try:
            subject = uuid.UUID(payload["sub"])
            token_id = uuid.UUID(payload["jti"])
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidTokenError() from exc

        if payload.get("typ") != "access":
            # Prevents a token minted for another purpose from being replayed
            # as an access token.
            raise InvalidTokenError()

        session_id: uuid.UUID | None = None
        if payload.get("sid"):
            try:
                session_id = uuid.UUID(str(payload["sid"]))
            except ValueError as exc:
                raise InvalidTokenError() from exc

        return AccessTokenClaims(
            subject=subject,
            token_id=token_id,
            issued_at=datetime.fromtimestamp(int(payload["iat"]), tz=UTC),
            expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
            role=str(payload.get("role", "")),
            session_id=session_id,
        )

    # -- helpers used by the auth service --------------------------------- #

    @staticmethod
    def access_token_lifetime(settings: Settings | None = None) -> timedelta:
        settings = settings or get_settings()
        return timedelta(minutes=settings.access_token_expire_minutes)

    @staticmethod
    def refresh_token_lifetime(settings: Settings | None = None) -> timedelta:
        settings = settings or get_settings()
        return timedelta(days=settings.refresh_token_expire_days)

    @staticmethod
    def refresh_family_lifetime(settings: Settings | None = None) -> timedelta:
        """Absolute ceiling for a refresh-token family.

        Rotation issues a new token each time, so without an absolute bound a
        session refreshed every 14 minutes would never end. An attacker holding a
        stolen token could keep a session alive indefinitely.
        """
        settings = settings or get_settings()
        return timedelta(days=settings.refresh_token_absolute_lifetime_days)


# --------------------------------------------------------------------------- #
# Password policy                                                             #
# --------------------------------------------------------------------------- #
#: Characters that disqualify an otherwise strong password. Password strength
#: comes from length and unpredictability, not from mandatory symbol classes.
_COMMON_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "12345678",
        "123456789",
        "qwertyuiop",
        "letmein123",
        "welcome123",
        "admin12345",
        "iloveyou1",
        "abc123456",
        "111111111",
        "changeme1",
        "construction",
        "fundipulse",
    }
)


@dataclass(frozen=True, slots=True)
class PasswordPolicyResult:
    ok: bool
    failures: tuple[str, ...]


def check_password_policy(password: str, settings: Settings | None = None) -> PasswordPolicyResult:
    """Evaluate a password against the configured policy.

    Returns *all* failures rather than the first, so a user filling in a form
    is not made to guess one rule at a time.

    Length is the dominant factor. A long passphrase passes comfortably, which
    is the behaviour that produces strong real-world passwords in a workforce
    that may not have encountered a password manager before.
    """
    settings = settings or get_settings()
    failures: list[str] = []

    if len(password) < settings.password_min_length:
        failures.append(f"must be at least {settings.password_min_length} characters")
    if len(password) > settings.password_max_length:
        # Also caps the cost of Argon2 on an adversarial input.
        failures.append(f"must be at most {settings.password_max_length} characters")
    if password.lower() in _COMMON_PASSWORDS:
        failures.append("is too common")

    has_letter = any(character.isalpha() for character in password)
    has_digit = any(character.isdigit() for character in password)
    if not (has_letter or has_digit):
        failures.append("must contain a letter or a number")

    return PasswordPolicyResult(ok=not failures, failures=tuple(failures))


def enforce_password_policy(password: str, settings: Settings | None = None) -> None:
    """Raise :class:`PasswordPolicyError` if the password fails the policy.

    Silently coerces rather than rejects in one respect: surrounding whitespace
    is stripped first, because a phone-keyboard paste is a common cause of an
    otherwise compliant password being rejected, and leading/trailing spaces are
    a well-known source of confusing login failures.
    """
    settings = settings or get_settings()
    candidate = password.strip()

    if not settings.enforce_password_policy:
        return

    result = check_password_policy(candidate, settings)
    if not result.ok:
        raise PasswordPolicyError(
            "The password " + ", ".join(result.failures) + ".",
        )
