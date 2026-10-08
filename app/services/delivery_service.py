"""Delivery of one-time tokens.

The delivery seam is deliberately narrow so a provider can be swapped without
touching a route or a service:

* services return a **plaintext token** exactly once;
* :class:`TokenDeliveryChannel` is the interface a provider must satisfy;
* :class:`ConsoleTokenDeliveryChannel` is used in development and in tests;
* :class:`SMTPTokenDeliveryChannel` delivers over SMTP in production;
* :class:`NullTokenDeliveryChannel` fails loudly when production has no provider.

SMTP is implemented with the standard library (:mod:`smtplib`) rather than a
vendor SDK. That is a deliberate choice for a deployment that cannot afford a
paid plan: there is one mail provider, the interface is three methods, and an SDK
would add a dependency tree, a transitive vulnerability surface, and a vendor
lock-in without removing a single line.

Failing loudly matters and is preserved in every channel. If delivery silently
no-op'd, a deployed system would report success while sending no email, and
every user would be permanently locked out of an account they had just created.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
import smtplib
import ssl

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

    Installed in production when no SMTP host is configured. Raising here
    turns "reset silently does nothing" into a loud, monitored failure, which is
    the safe direction for an unconfigured channel.
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


class SMTPTokenDeliveryChannel(TokenDeliveryChannel):
    """Delivers over SMTP using the standard library.

    Raises :class:`ServiceUnavailableError` on any failure, so every caller's
    existing failure handling applies unchanged: registration rolls back rather
    than leaving an account whose owner can never verify, while password reset
    and resend swallow the error so they cannot be used to enumerate accounts.

    Three deliberate choices:

    **Credentials never leave this module in any form.** The password is read
    from a ``SecretStr`` at call time and handed straight to ``smtplib``. No log
    record, no exception message and no attribute of this object carries it - the
    instance retains only host, port and the envelope sender, so neither a stack
    trace nor a ``vars()`` in a debugger can expose it.

    **A plain connection without STARTTLS is refused in production, not merely
    discouraged.** The send is refused with :class:`ServiceUnavailableError`
    rather than attempted, because a verification link is a single-use bearer
    token and sending one in cleartext would hand it to anyone on the path. The
    refusal is scoped to production so that a loopback relay used by a developer
    or a test double still works; outside production there is nothing to protect.

    **The sender is explicit.** The envelope sender falls back to the
    username, because most relays reject a ``From`` outside the domain the
    credentials authenticate against, and a silent fallback to a placeholder
    domain would produce mail nobody receives.
    """

    def __init__(self, settings: Settings) -> None:
        # Only non-secret connection coordinates are retained. See the class
        # docstring: this object should be safe to inspect.
        self._host = settings.email_smtp_host
        self._port = settings.email_smtp_port
        self._use_tls = settings.email_smtp_use_tls
        self._timeout = settings.email_smtp_timeout_seconds
        self._username = settings.email_smtp_username
        self._from = settings.email_smtp_from.strip() or settings.email_smtp_username.strip()
        self._from_name = settings.email_smtp_from_name.strip()
        # Captured at construction rather than re-read per send. The password is
        # deliberately *not* captured, so this instance never holds a secret;
        # the security posture, which is not a secret, is fixed for the lifetime
        # of the channel. Re-reading ambient settings inside send() would let a
        # test or a caller see different behaviour from the settings that chose
        # this channel in the first place.
        self._is_production = settings.is_production

    def send(self, message: OutboundMessage) -> None:
        if not message.to_email.strip():
            # A delivery with no recipient is an upstream programming error, and
            # smtplib would surface it as an opaque SMTPRecipientsRefused.
            logger.error(
                "Token delivery attempted with no recipient",
                extra={
                    "delivery_purpose": message.purpose,
                    "error_category": "delivery_configuration",
                },
            )
            raise ServiceUnavailableError("Email delivery failed. Please contact support.")

        email = _build_mime_message(message, from_address=self._from, from_name=self._from_name)

        try:
            self._transmit(email, to_address=message.to_email)
        except ServiceUnavailableError:
            raise
        except (smtplib.SMTPException, OSError, ssl.SSLError):
            # Logged, never returned. A driver error can echo the EHLO
            # capabilities or a rejected sender, none of which a caller needs and
            # some of which would disclose configuration detail.
            logger.error(
                "SMTP delivery failed",
                extra={
                    "delivery_purpose": message.purpose,
                    "delivery_recipient": _mask(message.to_email),
                    "smtp_host": self._host,
                    "smtp_port": self._port,
                    "error_category": "delivery_failure",
                },
                exc_info=True,
            )
            raise ServiceUnavailableError(
                "Email delivery is temporarily unavailable. Please try again shortly."
            ) from None

        # A delivery record, not an address book: the recipient is masked and the
        # token is absent.
        logger.info(
            "SMTP delivery accepted",
            extra={
                "delivery_purpose": message.purpose,
                "delivery_recipient": _mask(message.to_email),
                "smtp_host": self._host,
            },
        )

    def _transmit(self, email: EmailMessage, *, to_address: str) -> None:
        """Open, secure, authenticate, send, and always close.

        One ``with`` block so there is a single exit path that closes the socket,
        including on the failure paths.
        """
        # Implicit TLS (port 465) wraps the connection from the first byte, so it
        # needs SMTP_SSL rather than SMTP+STARTTLS.
        implicit_tls = not self._use_tls and self._port == 465

        # A verification link is a single-use bearer token, so production must
        # never put one on the wire in cleartext. The refusal is scoped to
        # production rather than being absolute: a local MailHog container or a
        # test double is a plain connection on loopback, and refusing those would
        # make the secure path impossible to exercise.
        if not self._use_tls and not implicit_tls and self._is_production:
            logger.error(
                "Refusing to send over an unencrypted SMTP connection in production",
                extra={
                    "smtp_host": self._host,
                    "smtp_port": self._port,
                    "error_category": "delivery_configuration",
                },
            )
            raise ServiceUnavailableError(
                "Email delivery is not configured securely. Contact support."
            )

        # Annotated as the base class: SMTP_SSL is a subclass, and mypy would
        # otherwise infer the narrower type from the first branch and reject the
        # plain SMTP client assigned in the other.
        client: smtplib.SMTP
        if implicit_tls:
            client = smtplib.SMTP_SSL(
                self._host, self._port, timeout=self._timeout, context=_tls_context()
            )
        else:
            client = smtplib.SMTP(self._host, self._port, timeout=self._timeout)

        with client:
            if self._use_tls:
                # Python 3.12 verifies certificates and hostnames by default;
                # starttls() with an explicit context keeps that true even if the
                # default context is ever changed.
                client.starttls(context=_tls_context())
                client.ehlo()

            if self._username:
                # Read at call time from the process settings rather than being
                # captured on the instance: this object must never hold a
                # secret, so that a stack trace or a debugger cannot expose one.
                client.login(
                    self._username,
                    get_settings().email_smtp_password.get_secret_value(),
                )

            client.send_message(email, to_addrs=[to_address])

    @property
    def is_configured(self) -> bool:
        return bool(self._host)


def _tls_context() -> ssl.SSLContext:
    """A verifying TLS context.

    System trust store, hostname checking, no relaxed verification.
    ``create_default_context`` sets all three, and is used instead of
    ``_create_unverified_context`` so the secure path is the only path.
    """
    return ssl.create_default_context()


def _build_mime_message(
    message: OutboundMessage, *, from_address: str, from_name: str
) -> EmailMessage:
    """Render an :class:`OutboundMessage` as a MIME message.

    ``EmailMessage`` rather than a hand-built string, so headers are encoded by
    the stdlib and a non-ASCII display name cannot corrupt them. The token
    appears only in the body, which is what a mail client renders.
    """
    sender = from_address or "no-reply@localhost"
    email = EmailMessage()
    email["Subject"] = message.subject
    email["From"] = formataddr((from_name, sender)) if from_name else sender
    email["To"] = message.to_email
    email["Date"] = formatdate(localtime=True)
    email["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2] or None)
    # Tells the receiving MTA the message was not composed by a person, which
    # keeps it out of auto-responders and vacation schedulers.
    email["Auto-Submitted"] = "auto-generated"
    email.set_content(message.body)
    return email


def get_delivery_channel(settings: Settings | None = None) -> TokenDeliveryChannel:
    """Select the delivery channel for the current environment.

    Three cases, and the third is the one that matters:

    * **development and test** - the console channel, unchanged. A developer must
      be able to complete a verification flow with no mail server.
    * **production with SMTP configured** - real delivery.
    * **production without SMTP configured** - :class:`NullTokenDeliveryChannel`,
      which raises.

    There is deliberately no fallback from production to the console channel. It
    would look like a working deployment while sending nothing, and the only
    symptom would be workers reporting they never received a verification email.
    """
    settings = settings or get_settings()

    if not settings.is_production:
        return ConsoleTokenDeliveryChannel()

    if settings.smtp_configured:
        return SMTPTokenDeliveryChannel(settings)

    return NullTokenDeliveryChannel()


def build_verification_email(
    *, recipient_name: str, token: str, expiry_hours: int
) -> OutboundMessage:
    """Compose the email-verification message.

    Plain text on purpose. A verification link is a single-use credential, and a
    worker is most likely to open it on the same phone they registered from,
    where a plain-text body is immediately selectable and readable. There is no
    marketing content: the only action in this message is the one the worker
    already came here to take.
    """
    return OutboundMessage(
        to_email="",
        subject="Confirm your FundiPulse email address",
        body=(
            f"Hello {recipient_name or 'there'},\n\n"
            "Confirm your email address to finish setting up your FundiPulse "
            "account. You need this before you can apply for work.\n\n"
            f"Open this link to confirm (valid for {expiry_hours} hours):\n"
            f"{_verification_link(token)}\n\n"
            "If the link has expired, request a new one from the app.\n\n"
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
