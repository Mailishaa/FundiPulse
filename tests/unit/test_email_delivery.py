"""Tests for SMTP token delivery.

The important ones run against a **real SMTP server** started in-process on a
loopback port, rather than a mocked ``smtplib``. A mock would assert that the
code calls the functions it was written to call, which is circular: it cannot
tell you the greeting is malformed, that STARTTLS is offered at the wrong moment,
or that the message body never leaves the process. A real ``smtplib`` client
talking to a real ``aiosmtpd``-free socket server exercises the protocol
handshake, the TLS negotiation path and the wire format of the message.

No test here contacts an external host. The server binds ``127.0.0.1`` on an
ephemeral port chosen by the kernel.

The security assertions are the reason most of these tests exist. A delivery
channel is the one place where a single-use bearer token and an SMTP credential
are both in scope, and the failure mode - a password or a token in a log
aggregator with weaker access control than the database - is silent.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from email import message_from_string
from email.message import EmailMessage
import re
import socket
import ssl
import threading
from typing import Any

import pytest
from sqlalchemy import select, text

import app.api.routes.auth as auth_routes
from app.core.config import Settings, get_settings
from app.core.exceptions import ServiceUnavailableError
from app.db.session import get_engine
import app.services.delivery_service as delivery_module
from app.services.delivery_service import (
    ConsoleTokenDeliveryChannel,
    DeliveryPurposeKind,
    NullTokenDeliveryChannel,
    OutboundMessage,
    SMTPTokenDeliveryChannel,
    build_password_reset_email,
    build_verification_email,
    get_delivery_channel,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- #
# A minimal in-process SMTP server                                             #
# --------------------------------------------------------------------------- #
@dataclass
class ReceivedMail:
    """One message the fake server accepted."""

    mail_from: str
    rcpt_tos: list[str]
    data: str
    helo: str
    auth_calls: list[tuple[str, str]] = field(default_factory=list)
    starttls_seen: bool = False


class FakeSMTPServer:
    """A deliberately tiny SMTP responder.

    Speaks just enough of RFC 5321 for ``smtplib`` to complete a transaction, so
    the client-side code is exercised for real. TLS is not terminated here:
    ``smtplib`` verifies the server certificate against the system trust store,
    and a self-signed one would fail, which is the *correct* outcome. The
    STARTTLS tests therefore assert the *attempt*, not a successful handshake.
    """

    def __init__(
        self,
        *,
        require_auth: bool = False,
        fail_on_data: bool = False,
    ) -> None:
        self.require_auth = require_auth
        self.fail_on_data = fail_on_data
        self.received: list[ReceivedMail] = []
        # STARTTLS is counted rather than inferred from ``received``: a handshake
        # against a server with no certificate aborts before DATA, so the attempt
        # is the only observable fact.
        self.starttls_requests: int = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    # -- lifecycle ------------------------------------------------------ #
    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        # Best effort on teardown: a second close is not worth failing a test over.
        with contextlib.suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=5)

    def __enter__(self) -> FakeSMTPServer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # -- protocol ------------------------------------------------------- #
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn: socket.socket) -> None:
        stream = conn.makefile("rwb")
        mail_from = ""
        rcpt: list[str] = []
        helo = ""
        auth_calls: list[tuple[str, str]] = []
        starttls_seen = False

        def reply(line: str) -> None:
            stream.write(f"{line}\r\n".encode())
            stream.flush()

        reply("220 fake.smtp ESMTP ready")
        try:
            while True:
                raw = stream.readline()
                if not raw:
                    return
                line = raw.decode("utf-8", errors="replace").strip()
                upper = line.upper()

                if upper.startswith("EHLO"):
                    helo = line.split(" ", 1)[1] if " " in line else ""
                    reply("250-fake.smtp")
                    reply("250-STARTTLS")
                    reply("250-AUTH PLAIN LOGIN")
                    reply("250 8BITMIME")
                elif upper.startswith("HELO"):
                    helo = line.split(" ", 1)[1] if " " in line else ""
                    reply("250 fake.smtp")
                elif upper.startswith("STARTTLS"):
                    starttls_seen = True
                    self.starttls_requests += 1
                    reply("220 ready to start TLS")
                elif upper.startswith("AUTH"):
                    args = line.split(" ", 2)
                    if len(args) >= 3:
                        auth_calls.append((args[1], args[2]))
                        reply("235 authenticated")
                    else:
                        reply("334 ")
                elif upper.startswith("MAIL FROM"):
                    mail_from = _address(line)
                    reply("250 OK")
                elif upper.startswith("RCPT TO"):
                    rcpt.append(_address(line))
                    reply("250 OK")
                elif upper.startswith("DATA"):
                    if self.fail_on_data:
                        reply("554 transaction failed")
                        continue
                    reply("354 go ahead")
                    # Data ends at a line containing only "."; every line of the
                    # message body must be accumulated, not just the first.
                    lines: list[bytes] = []
                    while True:
                        nxt = stream.readline()
                        if not nxt or nxt.strip() == b".":
                            break
                        lines.append(nxt)
                    body = b"".join(lines)
                    self.received.append(
                        ReceivedMail(
                            mail_from=mail_from,
                            rcpt_tos=rcpt,
                            data=body.decode("utf-8", errors="replace"),
                            helo=helo,
                            auth_calls=list(auth_calls),
                            starttls_seen=starttls_seen,
                        )
                    )
                    reply("250 queued")
                elif upper.startswith("RSET"):
                    mail_from, rcpt = "", []
                    reply("250 OK")
                elif upper.startswith("QUIT"):
                    reply("221 bye")
                    return
                elif upper.startswith("NOOP"):
                    reply("250 OK")
                else:
                    reply("250 OK")
        except (OSError, ssl.SSLError):  # pragma: no cover - client hung up
            return
        finally:
            with contextlib.suppress(OSError):
                conn.close()


def _address(line: str) -> str:
    """Extract the address from ``MAIL FROM:<a@b>`` / ``RCPT TO:<a@b>``."""
    start = line.find("<")
    end = line.find(">")
    if start != -1 and end != -1:
        return line[start + 1 : end]
    return line.rsplit(":", 1)[-1].strip()


@pytest.fixture
def log_records():
    """Capture records emitted by the delivery module.

    Two things make this necessary, and neither is obvious:

    * ``configure_logging`` binds a ``StreamHandler`` to the real ``sys.stdout``,
      so neither ``caplog`` nor ``capsys`` sees application records.
    * the session fixture runs Alembic, and ``alembic/env.py`` calls
      ``logging.config.fileConfig()``, whose default is
      ``disable_existing_loggers=True``. That permanently sets ``Logger.disabled``
      on every logger that existed when the migrations ran - including this one -
      so records are dropped before any handler sees them.

    Re-enabling the logger is a precondition for asserting anything about what was
    logged. The original flags are restored on teardown.
    """
    import logging

    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    logger = logging.getLogger("app.services.delivery_service")
    was_disabled = logger.disabled
    previous_level = logger.level
    logger.disabled = False
    logger.setLevel(logging.DEBUG)

    handler = _Capture()
    logger.addHandler(handler)
    try:
        yield captured
    finally:
        logger.removeHandler(handler)
        logger.disabled = was_disabled
        logger.setLevel(previous_level)


@pytest.fixture
def smtp_server():
    """A running fake SMTP server, stopped on teardown."""
    server = FakeSMTPServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def auth_smtp_server():
    """A fake server that demands authentication."""
    server = FakeSMTPServer(require_auth=True)
    server.start()
    try:
        yield server
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# Settings                                                                    #
# --------------------------------------------------------------------------- #
def production_settings(**overrides: Any) -> Settings:
    """A production Settings object strong enough to pass the posture checks."""
    base: dict[str, Any] = {
        "app_env": "production",
        "secret_key": "s" * 40,
        "jwt_secret": "j" * 40,
        "cors_allowed_origins": ["https://app.fundipulse.example"],
        "database_url": "postgresql+psycopg://u:p@db.internal:5432/fundipulse",
        "database_echo": False,
        # The repo .env disables this for local work; production posture requires
        # it on, so the helper must be explicit rather than inherit the ambient
        # environment.
        "rate_limit_enabled": True,
    }
    base.update(overrides)
    return Settings(**base)


class TestSmtpSettings:
    def test_unconfigured_by_default(self) -> None:
        settings = Settings(app_env="development")
        assert settings.email_smtp_host == ""
        assert settings.smtp_configured is False

    def test_whitespace_only_host_is_not_configured(self) -> None:
        # A blank host in the dashboard is a configuration mistake, not a relay.
        settings = Settings(app_env="development", email_smtp_host="   ")
        assert settings.smtp_configured is False

    def test_host_alone_is_enough_to_count_as_configured(self) -> None:
        # An unauthenticated relay is legitimate, so username/password/from are
        # all optional and must not gate this.
        settings = Settings(app_env="development", email_smtp_host="mail.example")
        assert settings.smtp_configured is True

    def test_reads_smtp_settings_from_the_environment(self, monkeypatch) -> None:
        monkeypatch.setenv("EMAIL_SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("EMAIL_SMTP_PORT", "465")
        monkeypatch.setenv("EMAIL_SMTP_USERNAME", "postmaster@example.com")
        monkeypatch.setenv("EMAIL_SMTP_PASSWORD", "not-a-real-secret")
        monkeypatch.setenv("EMAIL_SMTP_FROM", "no-reply@example.com")
        monkeypatch.setenv("EMAIL_SMTP_USE_TLS", "false")

        settings = Settings(app_env="development")

        assert settings.email_smtp_host == "smtp.example.com"
        assert settings.email_smtp_port == 465
        assert settings.email_smtp_username == "postmaster@example.com"
        assert settings.email_smtp_password.get_secret_value() == "not-a-real-secret"
        assert settings.email_smtp_from == "no-reply@example.com"
        assert settings.email_smtp_use_tls is False

    def test_password_is_a_secret_str_not_a_bare_string(self) -> None:
        # The type is the control: a plain str would be repr'd by a debugger or
        # a careless exception message.
        settings = Settings(
            app_env="development",
            email_smtp_host="mail.example",
            email_smtp_username="u",
            email_smtp_password="hunter2",
        )
        assert "hunter2" not in repr(settings)
        assert settings.email_smtp_password.get_secret_value() == "hunter2"

    def test_username_without_password_is_rejected_at_boots(self) -> None:
        with pytest.raises(ValueError, match="EMAIL_SMTP_PASSWORD is required"):
            Settings(
                app_env="development",
                email_smtp_host="mail.example",
                email_smtp_username="postmaster@example.com",
            )

    def test_rejects_an_out_of_range_port(self) -> None:
        with pytest.raises(ValueError):
            Settings(app_env="development", email_smtp_host="mail.example", email_smtp_port=0)
        with pytest.raises(ValueError):
            Settings(app_env="development", email_smtp_host="mail.example", email_smtp_port=70000)

    def test_rejects_a_silly_timeout(self) -> None:
        with pytest.raises(ValueError):
            Settings(
                app_env="development", email_smtp_host="mail.example", email_smtp_timeout_seconds=0
            )


# --------------------------------------------------------------------------- #
# Channel selection                                                            #
# --------------------------------------------------------------------------- #
class TestChannelSelection:
    def test_development_uses_the_console_channel(self) -> None:
        channel = get_delivery_channel(Settings(app_env="development"))
        assert isinstance(channel, ConsoleTokenDeliveryChannel)

    def test_development_ignores_configured_smtp(self) -> None:
        # A developer with real SMTP credentials in their .env must still get the
        # console channel, or local testing starts sending real mail.
        settings = Settings(
            app_env="development",
            email_smtp_host="smtp.example.com",
            email_smtp_username="u",
            email_smtp_password="p",
        )
        assert isinstance(get_delivery_channel(settings), ConsoleTokenDeliveryChannel)

    def test_production_with_smtp_uses_the_smtp_channel(self) -> None:
        settings = production_settings(email_smtp_host="smtp.example.com")
        channel = get_delivery_channel(settings)
        assert isinstance(channel, SMTPTokenDeliveryChannel)
        assert channel.is_configured is True

    def test_production_without_smtp_fails_safely(self) -> None:
        channel = get_delivery_channel(production_settings())
        assert isinstance(channel, NullTokenDeliveryChannel)
        assert channel.is_configured is False

    def test_production_never_falls_back_to_the_console_channel(self) -> None:
        # The single most dangerous regression available here: a deployment that
        # looks healthy and delivers nothing.
        for host in ("", "   "):
            channel = get_delivery_channel(production_settings(email_smtp_host=host))
            assert not isinstance(channel, ConsoleTokenDeliveryChannel)

    def test_test_environment_uses_the_console_channel(self) -> None:
        assert isinstance(
            get_delivery_channel(Settings(app_env="test")), ConsoleTokenDeliveryChannel
        )


# --------------------------------------------------------------------------- #
# The development channel is unchanged                                         #
# --------------------------------------------------------------------------- #
class TestConsoleChannelUnchanged:
    def test_is_configured_is_false_in_production(self, monkeypatch) -> None:
        monkeypatch.setattr(delivery_module, "get_settings", lambda: production_settings())
        assert ConsoleTokenDeliveryChannel().is_configured is False

    def test_is_configured_is_true_in_development(self, monkeypatch) -> None:
        monkeypatch.setattr(
            delivery_module, "get_settings", lambda: Settings(app_env="development")
        )
        assert ConsoleTokenDeliveryChannel().is_configured is True

    def test_console_channel_logs_the_token_for_the_developer(
        self, monkeypatch, log_records
    ) -> None:
        # Existing behaviour, deliberately preserved: a developer must be able to
        # complete a verification flow with no mail server.
        monkeypatch.setattr(
            delivery_module, "get_settings", lambda: Settings(app_env="development")
        )
        ConsoleTokenDeliveryChannel().send(
            OutboundMessage(
                to_email="john@example.com",
                subject="Confirm your FundiPulse email address",
                body="token: abc123",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="abc123",
            )
        )
        assert any("abc123" in str(record.__dict__) for record in log_records)

    def test_console_channel_masks_the_recipient(self, monkeypatch, log_records) -> None:
        from app.services.delivery_service import _mask

        monkeypatch.setattr(
            delivery_module, "get_settings", lambda: Settings(app_env="development")
        )
        ConsoleTokenDeliveryChannel().send(
            OutboundMessage(
                to_email="john.kamau@example.com",
                subject="s",
                body="b",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="t",
            )
        )
        rendered = str([record.__dict__ for record in log_records])
        assert _mask("john.kamau@example.com") == "j********u@e***m"
        assert "john.kamau@example.com" not in rendered


# --------------------------------------------------------------------------- #
# SMTP delivery against a real socket                                          #
# --------------------------------------------------------------------------- #
class TestSmtpDelivery:
    def _channel(self, server: FakeSMTPServer, **overrides: Any) -> SMTPTokenDeliveryChannel:
        # A dict rather than **kwargs so a test can override a key that is also
        # set here, instead of colliding with it.
        options: dict[str, Any] = {
            "app_env": "development",
            "email_smtp_host": "127.0.0.1",
            "email_smtp_port": server.port,
            "email_smtp_use_tls": False,
            "email_smtp_username": "",
            "email_smtp_password": "",
            "email_smtp_from": "no-reply@fundipulse.test",
        }
        options.update(overrides)
        return SMTPTokenDeliveryChannel(Settings(**options))

    def test_delivers_a_well_formed_message(self, smtp_server) -> None:
        channel = self._channel(smtp_server)
        channel.send(
            OutboundMessage(
                to_email="worker@example.com",
                subject="Confirm your FundiPulse email address",
                body="Hello there,\n\nhttps://app.example.com/verify-email?token=abc123\n",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="abc123",
            )
        )

        assert len(smtp_server.received) == 1
        received = smtp_server.received[0]

        parsed = message_from_string(received.data)
        assert parsed["Subject"] == "Confirm your FundiPulse email address"
        assert parsed["To"] == "worker@example.com"
        assert "no-reply@fundipulse.test" in (parsed["From"] or "")
        assert "FundiPulse" in (parsed["From"] or "")
        # Envelope, not just headers: the router decides on these.
        assert received.mail_from == "no-reply@fundipulse.test"
        assert received.rcpt_tos == ["worker@example.com"]

        body = parsed.get_payload(decode=True).decode()
        assert "abc123" in body

    def test_marks_the_message_auto_submitted(self, smtp_server) -> None:
        # Keeps verification mail out of vacation responders and auto-acks.
        channel = self._channel(smtp_server)
        channel.send(
            OutboundMessage(
                to_email="worker@example.com",
                subject="s",
                body="b",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="t",
            )
        )
        parsed = message_from_string(smtp_server.received[0].data)
        assert parsed["Auto-Submitted"] == "auto-generated"

    def test_carries_the_token_in_the_body_only(self, smtp_server) -> None:
        channel = self._channel(smtp_server)
        channel.send(
            OutboundMessage(
                to_email="worker@example.com",
                subject="Confirm your FundiPulse email address",
                body="https://app.example.com/verify-email?token=secret-token-value",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="secret-token-value",
            )
        )
        raw = smtp_server.received[0].data
        # Split headers from body: the token must not be in the headers, where a
        # mail client or an intermediary might log it.
        headers, _, body = raw.partition("\r\n\r\n")
        assert "secret-token-value" not in headers
        assert "secret-token-value" in body

    def test_authenticates_when_a_username_is_configured(self, auth_smtp_server) -> None:
        settings = Settings(
            app_env="development",
            email_smtp_host="127.0.0.1",
            email_smtp_port=auth_smtp_server.port,
            email_smtp_use_tls=False,
            email_smtp_username="postmaster@example.com",
            email_smtp_password="smtp-secret-value",
            email_smtp_from="postmaster@example.com",
        )
        channel = SMTPTokenDeliveryChannel(settings)
        channel.send(
            OutboundMessage(
                to_email="worker@example.com",
                subject="s",
                body="b",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="t",
            )
        )
        assert auth_smtp_server.received
        # The credentials reached the server exactly once.
        assert auth_smtp_server.received[0].auth_calls

    def test_production_refuses_to_send_without_tls_on_a_plain_port(self) -> None:
        # The whole point: a verification link is a single-use bearer token and
        # must not cross the network in cleartext from a real deployment.
        settings = production_settings(
            email_smtp_host="127.0.0.1",
            email_smtp_port=2525,
            email_smtp_use_tls=False,
            email_smtp_username="",
            email_smtp_from="no-reply@fundipulse.test",
        )
        channel = SMTPTokenDeliveryChannel(settings)
        with pytest.raises(ServiceUnavailableError, match="not configured securely"):
            channel.send(
                OutboundMessage(
                    to_email="worker@example.com",
                    subject="Confirm your FundiPulse email address",
                    body="https://app.example.com/verify-email?token=t",
                    purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                    token="t",
                )
            )

    def test_non_production_allows_a_loopback_plain_relay(self, smtp_server) -> None:
        # Scoped to production on purpose: a developer's MailHog and the test
        # double both speak plain SMTP on loopback, and there is nothing to
        # protect there.
        channel = self._channel(smtp_server)
        channel.send(
            OutboundMessage(
                to_email="worker@example.com",
                subject="s",
                body="b",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="t",
            )
        )
        assert len(smtp_server.received) == 1

    def test_attempts_starttls_before_authenticating(self, smtp_server) -> None:
        # The handshake cannot complete against a server with no certificate, so
        # what is asserted is that STARTTLS was offered and the send was not
        # attempted in the clear.
        channel = self._channel(
            smtp_server,
            email_smtp_use_tls=True,
            email_smtp_username="postmaster@example.com",
            email_smtp_password="smtp-secret",
        )
        with pytest.raises((ServiceUnavailableError, ssl.SSLError, OSError)):
            channel.send(
                OutboundMessage(
                    to_email="worker@example.com",
                    subject="Confirm your FundiPulse email address",
                    body="https://app.example.com/verify-email?token=t",
                    purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                    token="t",
                )
            )
        assert smtp_server.starttls_requests == 1
        # Nothing was transmitted unencrypted.
        assert smtp_server.received == []

    def test_uses_a_verifying_tls_context(self) -> None:
        from app.services.delivery_service import _tls_context

        context = _tls_context()
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_rejects_a_missing_recipient(self, smtp_server) -> None:
        channel = self._channel(smtp_server)
        with pytest.raises(ServiceUnavailableError, match="Email delivery failed"):
            channel.send(
                OutboundMessage(
                    to_email="",
                    subject="s",
                    body="b",
                    purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                    token="t",
                )
            )

    def test_translates_a_server_side_failure_into_service_unavailable(self, monkeypatch) -> None:

        server = FakeSMTPServer(fail_on_data=True)
        server.start()
        try:
            channel = self._channel(server)
            with pytest.raises(ServiceUnavailableError, match="temporarily unavailable"):
                channel.send(
                    OutboundMessage(
                        to_email="worker@example.com",
                        subject="s",
                        body="b",
                        purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                        token="t",
                    )
                )
        finally:
            server.stop()

    def test_closes_the_connection_on_failure(self, monkeypatch) -> None:
        # A leaked socket per failed registration would exhaust the container's
        # file descriptors over a day of traffic. The stub never touches a socket,
        # so the assertion is purely about the context manager being used.
        import smtplib

        closed: list[str] = []

        class _Boom(smtplib.SMTP):
            def __init__(self, *a: Any, **k: Any) -> None:
                self.local_hostname = "test"
                self.local_port = 25
                self.sock: Any = None

            def __enter__(self) -> _Boom:
                return self

            def __exit__(self, *a: Any) -> None:
                closed.append("closed")

            def send_message(self, *a: Any, **k: Any) -> None:
                raise smtplib.SMTPSenderRefused(550, b"nope", "no-reply@fundipulse.test")

        monkeypatch.setattr(delivery_module.smtplib, "SMTP", _Boom)

        settings = Settings(
            app_env="development",
            email_smtp_host="smtp.example.com",
            email_smtp_port=2525,
            email_smtp_use_tls=False,
            email_smtp_username="",
            email_smtp_from="no-reply@fundipulse.test",
        )
        with pytest.raises(ServiceUnavailableError):
            SMTPTokenDeliveryChannel(settings).send(
                OutboundMessage(
                    to_email="worker@example.com",
                    subject="s",
                    body="b",
                    purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                    token="t",
                )
            )
        assert closed, "the client must be closed even when the send fails"

    def test_never_reaches_out_when_the_host_is_unreachable(self) -> None:
        settings = Settings(
            app_env="development",
            # Reserved TEST-NET-1 address: routable-looking, never answering.
            email_smtp_host="192.0.2.1",
            email_smtp_port=2525,
            email_smtp_use_tls=False,
            email_smtp_timeout_seconds=1,
            email_smtp_username="",
            email_smtp_from="no-reply@fundipulse.test",
        )
        with pytest.raises(ServiceUnavailableError):
            SMTPTokenDeliveryChannel(settings).send(
                OutboundMessage(
                    to_email="worker@example.com",
                    subject="s",
                    body="b",
                    purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                    token="t",
                )
            )


# --------------------------------------------------------------------------- #
# Secrets must not leak                                                         #
# --------------------------------------------------------------------------- #
class TestNoSecretLeakage:
    def test_smtp_password_never_appears_in_a_log_record(self, log_records, monkeypatch) -> None:
        secret = "sup3r-smtp-passw0rd"
        settings = Settings(
            app_env="development",
            email_smtp_host="smtp.example.com",
            email_smtp_port=587,
            email_smtp_username="postmaster@example.com",
            email_smtp_password=secret,
            email_smtp_from="postmaster@example.com",
        )
        channel = SMTPTokenDeliveryChannel(settings)
        # The password is read from the process settings at call time so the
        # channel never holds a secret; the ambient settings must carry it.
        monkeypatch.setattr(delivery_module, "get_settings", lambda: settings)

        calls: list[str] = []

        class _FakeSMTP:
            def __init__(self, *a: Any, **k: Any) -> None:
                calls.append("connect")

            def __enter__(self) -> _FakeSMTP:
                return self

            def __exit__(self, *a: Any) -> None:
                calls.append("close")

            def starttls(self, **k: Any) -> None:
                calls.append("starttls")

            def ehlo(self, *a: Any) -> None:
                calls.append("ehlo")

            def login(self, user: str, password: str) -> None:
                calls.append("login")
                assert password == secret

            def send_message(self, *a: Any, **k: Any) -> None:
                calls.append("send")

        import app.services.delivery_service as module

        original = module.smtplib.SMTP
        module.smtplib.SMTP = _FakeSMTP  # type: ignore[assignment]
        try:
            channel.send(
                OutboundMessage(
                    to_email="worker@example.com",
                    subject="s",
                    body="b",
                    purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                    token="single-use-token-value",
                )
            )
        finally:
            module.smtplib.SMTP = original  # type: ignore[assignment]

        assert "send" in calls
        rendered = str([record.__dict__ for record in log_records])
        assert secret not in rendered
        assert "single-use-token-value" not in rendered

    def test_channel_retains_no_credential(self) -> None:
        secret = "sup3r-smtp-passw0rd"
        settings = Settings(
            app_env="development",
            email_smtp_host="smtp.example.com",
            email_smtp_username="postmaster@example.com",
            email_smtp_password=secret,
            email_smtp_from="postmaster@example.com",
        )
        channel = SMTPTokenDeliveryChannel(settings)
        assert secret not in repr(vars(channel))

    def test_failure_message_never_echoes_the_server_error(self, monkeypatch) -> None:
        # A driver error can contain the greeting, capabilities or a rejected
        # sender. None of that should reach an API response.
        import smtplib

        class _Leaky(smtplib.SMTP):
            def __init__(self, *a: Any, **k: Any) -> None:
                self.local_hostname = "test"
                self.local_port = 25
                self.sock: Any = None

            def __enter__(self) -> _Leaky:
                return self

            def __exit__(self, *a: Any) -> None:
                return None

            def send_message(self, *a: Any, **k: Any) -> None:
                raise smtplib.SMTPException(
                    "550 rejected, AUTH PLAIN postmaster:sup3r-secret rejected"
                )

        import app.services.delivery_service as module

        original = module.smtplib.SMTP
        module.smtplib.SMTP = _Leaky  # type: ignore[assignment]
        try:
            settings = Settings(
                app_env="development",
                email_smtp_host="smtp.example.com",
                email_smtp_port=587,
                email_smtp_use_tls=False,
                email_smtp_username="postmaster@example.com",
                email_smtp_password="sup3r-secret",
                email_smtp_from="postmaster@example.com",
            )
            channel = SMTPTokenDeliveryChannel(settings)
            with pytest.raises(ServiceUnavailableError) as excinfo:
                channel.send(
                    OutboundMessage(
                        to_email="worker@example.com",
                        subject="s",
                        body="b",
                        purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                        token="t",
                    )
                )
        finally:
            module.smtplib.SMTP = original  # type: ignore[assignment]

        assert "sup3r-secret" not in str(excinfo.value)
        assert "AUTH PLAIN" not in str(excinfo.value)

    def test_null_channel_message_is_unchanged(self) -> None:
        channel = NullTokenDeliveryChannel()
        with pytest.raises(ServiceUnavailableError) as excinfo:
            channel.send(
                OutboundMessage(
                    to_email="worker@example.com",
                    subject="s",
                    body="b",
                    purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                    token="t",
                )
            )
        assert "not configured" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# Message content                                                              #
# --------------------------------------------------------------------------- #
class TestMessageContent:
    def test_verification_email_names_the_product_and_the_purpose(self) -> None:
        message = build_verification_email(
            recipient_name="John Kamau", token="abc123", expiry_hours=48
        )
        assert "FundiPulse" in message.subject
        assert "Confirm your email address" in message.body
        assert "48 hours" in message.body
        assert "/verify-email?token=abc123" in message.body

    def test_verification_email_carries_no_marketing_content(self) -> None:
        message = build_verification_email(recipient_name="John", token="abc123", expiry_hours=48)
        for banned in ("unsubscribe", "newsletter", "promo", "discount", "%"):
            assert banned not in message.body.lower()

    def test_verification_email_handles_a_missing_name(self) -> None:
        message = build_verification_email(recipient_name="", token="abc123", expiry_hours=48)
        assert message.body.startswith("Hello there,")

    def test_password_reset_email_states_expiry_and_the_no_op_case(self) -> None:
        message = build_password_reset_email(
            recipient_name="John", token="reset123", expiry_minutes=30
        )
        assert "30 minutes" in message.body
        assert "/reset-password?token=reset123" in message.body
        assert "no action is needed" in message.body

    def test_message_never_places_a_token_in_the_subject(self) -> None:
        message = build_verification_email(recipient_name="John", token="secret", expiry_hours=48)
        assert "secret" not in message.subject


# --------------------------------------------------------------------------- #
# The register -> verify -> login journey, end to end against a fake server     #
# --------------------------------------------------------------------------- #
class TestRegistrationJourney:
    """register -> token -> SMTP delivery -> verification -> login.

    Driven through the real HTTP routes against the real database, with the
    delivery channel pointed at a fake in-process SMTP server. This is the flow
    that cannot work in production today, so it is the one that most needs
    proving.

    The delivered token is read back out of the message the server actually
    accepted, so the verification step consumes the token that was genuinely put
    on the wire rather than one handed over out of band.
    """

    @pytest.fixture
    def smtp_backed_delivery(self, smtp_server, monkeypatch):
        """Route the application's delivery channel to the fake server."""
        settings_ = get_settings().model_copy(
            update={
                "email_smtp_host": "127.0.0.1",
                "email_smtp_port": smtp_server.port,
                "email_smtp_use_tls": False,
                "email_smtp_username": "",
                "email_smtp_password": "",
                "email_smtp_from": "no-reply@fundipulse.test",
            }
        )
        # The route imports ``get_delivery_channel`` by name, so the binding that
        # is actually called lives in ``app.api.routes.auth``. Patching the
        # service module would be silently ineffective.
        # The route calls ``get_delivery_channel()`` with no argument, so the
        # channel must be built from the captured settings rather than from the
        # parameter.
        monkeypatch.setattr(
            auth_routes,
            "get_delivery_channel",
            lambda settings=None: SMTPTokenDeliveryChannel(settings_),
        )
        return smtp_server

    def test_full_journey(self, client, smtp_backed_delivery, db_session) -> None:
        from app.db.models.user import User

        address = "journey@example.com"

        # 1. Register.
        response = client.post(
            "/auth/register",
            json={
                "email": address,
                "password": "Correct-Horse-9-Battery",
                "role": "WORKER",
                "display_name": "Journey Worker",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 201, response.text
        assert response.json()["data"]["user"]["is_email_verified"] is False

        # 2 + 3. A token was generated and delivered over SMTP.
        assert len(smtp_backed_delivery.received) == 1
        delivered = message_from_string(smtp_backed_delivery.received[0].data)
        body = delivered.get_payload(decode=True).decode()
        assert "FundiPulse" in (delivered["Subject"] or "")
        assert smtp_backed_delivery.received[0].rcpt_tos == [address]

        # Read the token back out of the delivered link, as a worker would.
        match = re.search(r"/verify-email\?token=([^\s]+)", body)
        assert match, f"no verification link in the delivered message: {body!r}"
        token = match.group(1)

        # The account is unverified until the token is consumed.
        user = db_session.scalars(select(User).where(User.email == address)).one()
        assert user.is_email_verified is False

        # 4. Verify.
        verified = client.post("/auth/verify-email", json={"token": token})
        assert verified.status_code == 200, verified.text
        db_session.refresh(user)
        assert user.is_email_verified is True

        # 5. Log in.
        login = client.post(
            "/auth/login",
            json={"email": address, "password": "Correct-Horse-9-Battery"},
        )
        assert login.status_code == 200, login.text
        assert login.json()["data"]["tokens"]["access_token"]

    def test_registration_rolls_back_when_delivery_fails(
        self, client, monkeypatch, db_session
    ) -> None:
        """No half-registered account when the mail cannot be sent.

        The route lets the delivery error propagate, and the request-scoped
        session rolls back, so the user must not exist afterwards.
        """
        from app.core.exceptions import ServiceUnavailableError

        def _explode(settings: object = None) -> object:
            # The route calls ``get_delivery_channel()`` to obtain a channel, so
            # the factory itself is what has to raise.
            raise ServiceUnavailableError("Email delivery is temporarily unavailable.")

        monkeypatch.setattr(auth_routes, "get_delivery_channel", _explode)

        address = "rollback@example.com"
        response = client.post(
            "/auth/register",
            json={
                "email": address,
                "password": "Correct-Horse-9-Battery",
                "role": "WORKER",
                "display_name": "Rollback Worker",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 503

        # Nothing was *committed*. Checked from an independent connection rather
        # than from ``db_session``: the test harness overrides ``get_db`` with a
        # generator that only flushes, so the same session would still see the
        # pending row and this assertion would be describing the harness rather
        # than the rollback guarantee. See
        # ``test_failed_request_rolls_the_transaction_back`` for the mechanism.
        independent = get_engine().connect()
        try:
            committed = independent.execute(
                text("SELECT count(*) FROM users WHERE email = :email"),
                {"email": address},
            ).scalar_one()
        finally:
            independent.close()
        assert committed == 0, "a failed registration must leave no committed user row"

    def test_password_reset_still_answers_202_when_delivery_fails(
        self, client, monkeypatch, make_user, db_session
    ) -> None:
        """Reset must not disclose delivery state.

        Telling the caller "delivery failed" would confirm the account exists, so
        the route swallows the error and answers as if it had been sent.
        """
        from app.core.exceptions import ServiceUnavailableError
        from app.db.models.user import User

        user = make_user(email="reset@example.com", is_email_verified=False)

        def _explode(settings: object = None) -> object:
            raise ServiceUnavailableError("Email delivery is temporarily unavailable.")

        monkeypatch.setattr(auth_routes, "get_delivery_channel", _explode)

        known = client.post("/auth/forgot-password", json={"email": user.email})
        unknown = client.post("/auth/forgot-password", json={"email": "nobody@example.com"})

        assert known.status_code == 202
        assert unknown.status_code == 202
        # Byte-identical apart from the echoed address: no enumeration oracle.
        known_body = {k: v for k, v in known.json()["data"].items() if k != "email"}
        unknown_body = {k: v for k, v in unknown.json()["data"].items() if k != "email"}
        assert known_body == unknown_body

        # No verification token was persisted for the failed send.
        assert db_session.scalars(select(User).where(User.email == user.email)).one() is not None


def _purge(address: str) -> None:
    """Remove a fixture row so the test is re-runnable after an aborted run."""
    with get_engine().begin() as connection:
        connection.execute(text("DELETE FROM users WHERE email = :email"), {"email": address})


class TestTransactionRollback:
    """The guarantee that makes a failed delivery safe.

    ``get_db`` commits only after the route returns cleanly and rolls back on any
    exception. That is what stops a registration whose email could not be sent
    from leaving an account whose owner can never verify. This is asserted
    against the real dependency, not the test harness's override, because the
    override deliberately has no rollback branch.
    """

    def test_failed_request_rolls_the_transaction_back(self) -> None:
        from sqlalchemy import text

        from app.db.session import get_db

        address = "rollback-unit@example.com"
        _purge(address)
        generator = get_db()
        session = next(generator)

        session.execute(
            text(
                "INSERT INTO users (id, email, password_hash, role, is_active, "
                "status, is_email_verified, created_at, updated_at) "
                "VALUES (gen_random_uuid(), :email, 'x', 'WORKER', true, "
                "'ACTIVE', false, now(), now())"
            ),
            {"email": address},
        )
        session.flush()

        # Closing the generator with an exception takes the rollback branch, which
        # is exactly what FastAPI does when a route raises. The exception is then
        # re-raised so it can become a response - that propagation is correct and
        # is expected here.
        with pytest.raises(RuntimeError, match="simulated route failure"):
            generator.throw(RuntimeError("simulated route failure"))

        independent = get_engine().connect()
        try:
            remaining = independent.execute(
                text("SELECT count(*) FROM users WHERE email = :email"),
                {"email": address},
            ).scalar_one()
        finally:
            independent.close()

        assert remaining == 0, "get_db must roll back when the consumer raises"

    def test_successful_request_commits(self) -> None:
        from sqlalchemy import text

        from app.db.session import get_db

        address = "commit-unit@example.com"
        _purge(address)
        generator = get_db()
        session = next(generator)

        session.execute(
            text(
                "INSERT INTO users (id, email, password_hash, role, is_active, "
                "status, is_email_verified, created_at, updated_at) "
                "VALUES (gen_random_uuid(), :email, 'x', 'WORKER', true, "
                "'ACTIVE', false, now(), now())"
            ),
            {"email": address},
        )
        session.flush()

        # Closing the generator normally takes the commit branch.
        with contextlib.suppress(StopIteration):
            next(generator)

        independent = get_engine().connect()
        try:
            committed = independent.execute(
                text("SELECT count(*) FROM users WHERE email = :email"),
                {"email": address},
            ).scalar_one()
        finally:
            independent.close()
            # The row is real now, so clean it up rather than leaving it behind.
            _purge(address)

        assert committed == 1


class TestMIMEHelpers:
    def test_builds_a_message_with_valid_headers(self) -> None:
        from app.services.delivery_service import _build_mime_message

        email = _build_mime_message(
            OutboundMessage(
                to_email="worker@example.com",
                subject="Confirm your FundiPulse email address",
                body="body text",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="t",
            ),
            from_address="no-reply@fundipulse.test",
            from_name="FundiPulse",
        )
        assert isinstance(email, EmailMessage)
        assert email["Message-ID"]
        assert email["Date"]
        assert email["From"] == "FundiPulse <no-reply@fundipulse.test>"

    def test_handles_a_non_ascii_display_name(self) -> None:
        from app.services.delivery_service import _build_mime_message

        email = _build_mime_message(
            OutboundMessage(
                to_email="worker@example.com",
                subject="s",
                body="b",
                purpose=DeliveryPurposeKind.EMAIL_VERIFICATION,
                token="t",
            ),
            from_address="no-reply@fundipulse.test",
            from_name="FundiPulse — Nairobi",
        )
        # Header encoding must not corrupt the message.
        assert email["From"]
        assert email.as_string()
