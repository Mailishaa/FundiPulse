"""Email normalisation and the reuse-protection pre-check.

Every place that accepts an email address routes through this module, so the
uniqueness rule enforced by the database cannot be defeated by a caller that
forgets to lower-case.
"""

from __future__ import annotations

import re

from email_validator import EmailNotValidError, EmailSyntaxError, validate_email

from app.core.exceptions import ValidationError

#: Characters permitted in the local part beyond alphanumerics. "+" is included
#: deliberately: it is a standard alias separator, and refusing it would reject
#: addresses that real users type every day. Aliases are kept *distinct* rather
#: than folded together - see the note below on Gmail-style dot folding.
_ALLOWED_SPECIALS: frozenset[str] = frozenset("._-+")

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def normalise_email(raw: str) -> str:
    """Validate and canonicalise an email address.

    Returns the lower-cased, trimmed form. Raises :class:`ValidationError` with a
    generic message on failure - the specific reason an address is invalid is not
    useful to a legitimate user, and a detailed reason would help an attacker
    probe for valid addresses.
    """
    if not isinstance(raw, str):  # pragma: no cover - Pydantic guarantees str
        raise ValidationError("A valid email address is required.")

    candidate = _CONTROL_CHARACTERS.sub("", raw).strip()
    if not candidate:
        raise ValidationError("A valid email address is required.")

    try:
        result = validate_email(
            candidate,
            check_deliverability=False,
            allow_smtputf8=True,
            allow_display_name=False,
        )
    except (EmailSyntaxError, EmailNotValidError) as exc:
        raise ValidationError("A valid email address is required.") from exc

    # Deliberately not normalised any further. Gmail-style dot/plus folding would
    # make two visibly different addresses collide, which is more surprising than
    # it is helpful, and it silently breaks recovery for users who expect their
    # address to work verbatim.
    normalised = result.normalized.lower()
    if not normalised.endswith("@" + (result.domain or "").lower()):
        raise ValidationError("A valid email address is required.")
    local_part = normalised[: -(len(result.domain or "") + 1)]
    if not local_part:
        raise ValidationError("A valid email address is required.")
    if any(
        character not in _ALLOWED_SPECIALS for character in local_part if not character.isalnum()
    ):
        # Only these specials are conventional. Anything else is far more likely
        # to be a malformed address or an injection attempt than a real one.
        raise ValidationError("A valid email address is required.")
    return normalised


def mask_email(email: str) -> str:
    """Produce a masked address safe to include in a notification payload.

    Used in audit metadata and log context so a support conversation can confirm
    *which* address was involved without the log becoming a list of addresses.
    """
    if "@" not in email:
        return "***"
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    masked_domain = "***" if len(domain) <= 4 else f"{domain[0]}***{domain[-1]}"
    return f"{masked_local}@{masked_domain}"
