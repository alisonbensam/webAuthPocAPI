"""
Device Model — In-memory data store for the WebAuthn POC.

Each record represents a device assignment. A device is onboarded via
an Invitation Token (no username/password). Each device can have ONE registered
passkey at a time. When a new device registers with a valid invitation token, the
old credential is replaced and the previous refresh token is revoked.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class DeviceRecord(BaseModel):
    """
    Represents a single device record.

    Fields:
        location: Clinic / site the device belongs to (e.g., "Clinic 1")
        device_id: Unique device identifier (e.g., "DEVICE001") — the table key
        company_email: Company email address associated with this device
        credential_id: WebAuthn credential ID (base64url) — set after registration
        public_key: WebAuthn public key (PEM) — set after registration
        invitation_token: One-time onboarding token (e.g., "INV-7QX4-82PA-KLM9")
        invitation_token_expiry: When the invitation token expires (default 24h)
        invitation_token_used: True once the token has been consumed by a registration
        refresh_token: JWT refresh token — issued after successful registration/auth
        refresh_token_expiry: When the refresh token expires (365 days from issue)
        registered_at: Timestamp when the passkey was registered
        last_login: Timestamp of the most recent successful login
        status: Current status (not_registered, active, revoked)
    """
    location: str
    device_id: str
    company_email: str
    credential_id: Optional[str] = None
    public_key: Optional[str] = None
    invitation_token: Optional[str] = None
    invitation_token_expiry: Optional[datetime] = None
    invitation_token_used: bool = False
    refresh_token: Optional[str] = None
    refresh_token_expiry: Optional[datetime] = None
    registered_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    status: str = "not_registered"


# -------------------------------------------------------------------
# In-Memory "Database" — Device Table
# -------------------------------------------------------------------
# This replaces a real database. The table is keyed by device_id.
# Each entry starts with:
#   - credential_id = None        (no passkey registered yet)
#   - public_key = None
#   - invitation_token = None     (admin generates one on demand)
#   - invitation_token_used = False
#   - refresh_token = None
#   - status = "not_registered"
#
# All data is synthetic test data — no real PHI/PII.
# -------------------------------------------------------------------

DEVICE_TABLE: dict[str, DeviceRecord] = {}

# 10 sample device assignments (synthetic data only)
_seed_records = [
    ("Clinic 1", "DEVICE001", "alison@clinic.com"),
    ("Clinic 1", "DEVICE002", "john@clinic.com"),
    ("Clinic 2", "DEVICE003", "mary@clinic.com"),
    ("Clinic 2", "DEVICE004", "david@clinic.com"),
    ("Clinic 3", "DEVICE005", "susan@clinic.com"),
    ("Clinic 3", "DEVICE006", "peter@clinic.com"),
    ("Clinic 4", "DEVICE007", "linda@clinic.com"),
    ("Clinic 4", "DEVICE008", "james@clinic.com"),
    ("Clinic 5", "DEVICE009", "karen@clinic.com"),
    ("Clinic 5", "DEVICE010", "robert@clinic.com"),
]

for _location, _device_id, _email in _seed_records:
    DEVICE_TABLE[_device_id] = DeviceRecord(
        location=_location,
        device_id=_device_id,
        company_email=_email,
    )
