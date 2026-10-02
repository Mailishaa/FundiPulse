"""Delivery of one-time tokens.

This milestone has **no email provider wired up**. That is a deliberate gap, not
an oversight: choosing between SES, Postmark and an African SMS gateway is a
product decision with cost and deliverability consequences, and guessing wrong
would be worse than leaving it explicit.

What exists instead is the seam:

* services return a **plaintext token** exactly once;
* :class:`TokenDeliveryChannel` is the interface a provider must satisfy;
* :class:`ConsoleTokenDeliveryChannel` is used in development and in tests;
* :class:`NullTokenDeliveryChannel` fails loudly in production.

Failing loudly matters: if this silently no-op'd, a deployed system would issue no
reset emails while reporting success, and users would be permanently locked out.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from app.core.config import Settings, get_settings
from app.core.exceptions import ServiceUnavailableError
from app.core.logging import get_logger

logger = get_logger(__name__)


class DeliveryPurposeKind:
    EMAIL_VERIFICATION = "email_verification"
    # Message-kind identifier, not a credential.
    PASSWORD_RESET = "password_reset"  # noqa: S105  # nosec B105
    REFERENCE_INVITATION = "reference_invitation"
    VERIFICATION_INVITATION = "verification_invitation"


@dataclass(frozen=True, slots=True)
class OutboundMessage:
    """A message to deliver.

    ``token`` is the one-time plaintext. It is never logged, never persisted and
    never returned by an API response in production.
    """

    to_email: str
    subject: str
    body: str
    purpose: str
    token: str | None = None


class TokenDeliveryChannel(abc.ABC):
    """Interface for anything that can deliver a one-time token."""

    @abc.abstractmethod
    def send(self, message: OutboundMessage) -> None:
        """Deliver the message. Raise on failure so the caller can react."""

    @property
    @abc.abstractmethod
    def is_configured(self) -> bool:
        """Whether this channel can actually deliver."""


class ConsoleTokenDeliveryChannel(TokenDeliveryChannel):
    """Writes the message to the log.

    Development and tests only. It logs the token deliberately, because a
    developer needs to complete a flow without a mail server - and this is the
    one place where a token in a log is acceptable, because the audience is the
    developer and the environment is not reachable by anyone else.

    :meth:`is_configured` refuses to be used in production, so this cannot be
    selected by accident in a real deployment.
    """

    def send(self, message: OutboundMessage) -> None:
        log = logger.warning
        log(
            "DELIVERY (development only)",
            extra={
                "delivery_purpose": message.purpose,
                "delivery_recipient": _mask(message.to_email),
                "delivery_subject": message.subject,
                "delivery_token": message.token,
            },
        )

    @property
    def is_configured(self) -> bool:
        return not get_settings().is_production


class NullTokenDeliveryChannel(TokenDeliveryChannel):
    """A placeholder that refuses to pretend.

    Installed in production until a real provider is configured. Raising here
    turns "reset silently does nothing" into a loud, monitored failure, which is
    the safe direction for an unimplemented channel.
    """

    def send(self, message: OutboundMessage) -> None:
        logger.error(
            "Token delivery attempted with no configured provider",
            extra={
                "delivery_purpose": message.purpose,
                "delivery_recipient": _mask(message.to_email),
            },
        )
        raise ServiceUnavailableError(
            "Email delivery is not configured. Contact support to have your email address verified."
        )

    @property
    def is_configured(self) -> bool:
        return False


def get_delivery_channel(settings: Settings | None = None) -> TokenDeliveryChannel:
    """Select the delivery channel for the current environment.

    Phase 2 ships the console and null channels only. A real provider is a
    drop-in addition here - it implements
    :class:`TokenDeliveryChannel` and is selected by configuration.
    """
    settings = settings or get_settings()
    if settings.is_production:
        # Until a provider exists, this raises on use rather than silently
        # dropping tokens. See the module docstring.
        return NullTokenDeliveryChannel()
    return ConsoleTokenDeliveryChannel()


def build_verification_email(
    *, recipient_name: str, token: str, expiry_hours: int
) -> OutboundMessage:
    """Compose the email-verification message."""
    return OutboundMessage(
        to_email="",
        subject="Confirm your FundiPulse email address",
        body=(
            f"Hello {recipient_name or 'there'},\n\n"
            "Confirm your email address to finish setting up your FundiPulse "
            f"account.\n\nVerification link (valid {expiry_hours} hours):\n"
            f"{_verification_link(token)}\n\n"
            "If you did not create this account you can ignore this message.\n"
        ),
        purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
        token=token,
    )


def build_password_reset_email(
    *, recipient_name: str, token: str, expiry_minutes: int
) -> OutboundMessage:
    """Compose the password-reset message."""
    return OutboundMessage(
        to_email="",
        subject="Reset your FundiPulse password",
        body=(
            f"Hello {recipient_name or 'there'},\n\n"
            "Use the link below to choose a new password. It can be used once "
            f"and expires in {expiry_minutes} minutes.\n\n"
            f"{_reset_link(token)}\n\n"
            "If you did not request a reset, no action is needed - your "
            "password has not changed.\n"
        ),
        purpose=DeliveryPurposeKind.PASSWORD_RESET,
        token=token,
    )


def _verification_link(token: str) -> str:
    settings = get_settings()
    base = _frontend_base_url(settings)
    return f"{base}/verify-email?token={token}"


def _reset_link(token: str) -> str:
    settings = get_settings()
    base = _frontend_base_url(settings)
    return f"{base}/reset-password?token={token}"


def _frontend_base_url(settings: Settings) -> str:
    """Best-effort front-end origin for building links.

    Falls back to an empty string so a link is still readable in the development
    log even when no front end is configured.
    """
    origins = settings.cors_allowed_origins
    return origins[0] if origins else ""


def _mask(email: str) -> str:
    from app.utils.email import mask_email

    return mask_email(email)
