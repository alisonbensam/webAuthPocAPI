"""
Token Service — JWT Access Token and Refresh Token management.

This service handles:
- Generating short-lived access tokens (15 min)
- Generating long-lived refresh tokens (365 days)
- Validating and decoding tokens
- Revoking tokens (by clearing from the device record)
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

# -------------------------------------------------------------------
# JWT Configuration
# -------------------------------------------------------------------
# In production, these would be loaded from environment variables.
# For this POC, we use a hardcoded secret.
# -------------------------------------------------------------------
SECRET_KEY = "webauthn-poc-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 365


def create_access_token(device_id: str) -> str:
    """
    Create a short-lived JWT access token.

    Args:
        device_id: The device identifier to encode in the token

    Returns:
        Encoded JWT string valid for 15 minutes
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": device_id,
        "exp": expire,
        "type": "access",
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(device_id: str) -> tuple[str, datetime]:
    """
    Create a long-lived JWT refresh token (365 days).

    The refresh token allows the device to obtain new access tokens
    without re-authenticating. When a device is replaced, the old
    refresh token is invalidated by overwriting it in the device record.

    Args:
        device_id: The device identifier to encode in the token

    Returns:
        Tuple of (encoded JWT string, expiry datetime)
    """
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": device_id,
        "exp": expire,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16),  # Unique token ID for revocation tracking
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, expire


def validate_token(token: str, expected_type: str = "access") -> Optional[dict]:
    """
    Validate and decode a JWT token.

    Args:
        token: The JWT string to validate
        expected_type: Expected token type ('access' or 'refresh')

    Returns:
        Decoded payload dict if valid, None if invalid/expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != expected_type:
            return None
        return payload
    except JWTError:
        return None
