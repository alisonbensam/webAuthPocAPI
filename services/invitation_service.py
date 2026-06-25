"""
Invitation Token Service — Onboarding tokens for device registration.

Invitation tokens replace the old username/password onboarding. An administrator
generates a token for a specific employee; the employee uses it once to register
their device's passkey.

Token characteristics (per spec):
- Generated only when needed (admin action).
- One-time use.
- Expires after a configurable period (default 24 hours).
- Automatically deleted after successful registration.
- Can be revoked before use.
- Cannot be reused.
- Must belong to a specific employee/device assignment.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from models.device import DeviceRecord

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
# Configurable expiry window for invitation tokens. Default 24 hours.
INVITATION_TOKEN_HOURS = 24

# Alphabet for the random token blocks. Uppercase letters + digits.
_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def generate_invitation_token() -> str:
    """
    Generate a cryptographically random invitation token.

    Format: INV-XXXX-XXXX-XXXX  (e.g., "INV-7QX4-82PA-KLM9")
    Uses secrets.choice for cryptographic randomness (not the `random` module).

    Returns:
        A new invitation token string.
    """
    blocks = [
        "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(4))
        for _ in range(3)
    ]
    return "INV-" + "-".join(blocks)


def issue_invitation_token(record: DeviceRecord) -> DeviceRecord:
    """
    Issue (or replace) an invitation token on an employee record.

    Stores the token, sets the expiry (now + INVITATION_TOKEN_HOURS), and resets
    the used flag to False. Any previously issued-but-unused token is overwritten.

    Args:
        record: The employee/device record to issue the token for.

    Returns:
        The updated record.
    """
    record.invitation_token = generate_invitation_token()
    record.invitation_token_expiry = datetime.now(timezone.utc) + timedelta(
        hours=INVITATION_TOKEN_HOURS
    )
    record.invitation_token_used = False
    return record


def revoke_invitation_token(record: DeviceRecord) -> DeviceRecord:
    """
    Revoke an invitation token before it is used.

    Deletes the token and clears its expiry so it can no longer be validated.

    Args:
        record: The employee/device record whose token should be revoked.

    Returns:
        The updated record.
    """
    record.invitation_token = None
    record.invitation_token_expiry = None
    record.invitation_token_used = False
    return record


def validate_invitation_token(record: DeviceRecord, token: str) -> Optional[str]:
    """
    Validate an invitation token against an employee record.

    Checks, in order:
    1. The record has an invitation token issued.
    2. The token has not already been used (one-time use).
    3. The token has not expired.
    4. The provided token matches the stored token.

    Args:
        record: The employee/device record to validate against.
        token: The invitation token supplied by the user.

    Returns:
        None if the token is valid; otherwise a short reason string
        ("no_token", "used", "expired", "mismatch").
    """
    if not record.invitation_token:
        return "no_token"

    if record.invitation_token_used:
        return "used"

    if record.invitation_token_expiry is None:
        return "expired"

    # Normalize expiry to timezone-aware UTC for comparison
    expiry = record.invitation_token_expiry
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expiry:
        return "expired"

    # Constant-time comparison to avoid timing attacks
    if not secrets.compare_digest(record.invitation_token, token):
        return "mismatch"

    return None


def consume_invitation_token(record: DeviceRecord) -> DeviceRecord:
    """
    Consume an invitation token after a successful registration.

    Per spec, the token is automatically DELETED after successful registration.
    We also flag it as used for clarity in the admin view's audit trail.

    Args:
        record: The employee/device record whose token was just used.

    Returns:
        The updated record.
    """
    record.invitation_token_used = True
    record.invitation_token = None
    record.invitation_token_expiry = None
    return record
