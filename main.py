"""
WebAuthn Device Registration POC — FastAPI Backend

This is the main entry point for the backend server.
Run with: uvicorn main:app --reload --port 8000

Architecture:
- /register/*           → WebAuthn registration (invitation-token onboarding + create passkey)
- /auth/*               → WebAuthn authentication (use passkey)
- /token/refresh        → Refresh access token using refresh token
- /logout               → Invalidate refresh token
- /device               → Get current device registration info
- /admin/devices        → List all employee/device records (admin)
- /admin/revoke         → Force-revoke a device (admin)
- /admin/generate-token → Issue an invitation token for an employee (admin)
- /admin/revoke-token   → Revoke an unused invitation token (admin)
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models.device import DEVICE_TABLE, DeviceRecord
from services.token_service import (
    create_access_token,
    create_refresh_token,
    validate_token,
)
from services.webauthn_service import (
    generate_registration_options,
    verify_registration,
    generate_authentication_options,
    verify_authentication,
)
from services.invitation_service import (
    issue_invitation_token,
    revoke_invitation_token,
    validate_invitation_token,
    consume_invitation_token,
)

# -------------------------------------------------------------------
# FastAPI Application Setup
# -------------------------------------------------------------------
app = FastAPI(
    title="WebAuthn Device Registration POC",
    description="Proof of Concept for device registration and replacement using WebAuthn/Passkeys",
    version="1.0.0",
)

# CORS configuration — allow the React frontend to make requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://web-auth-poc-ui.vercel.app",  # Mobile PWA
        "https://web-auth-poc-admin-ui.app",  # Admin Portal
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# Admin Configuration
# -------------------------------------------------------------------
# Simple admin API key for the POC. In production this would be replaced
# with proper role-based authentication (e.g., an admin JWT scope).
# The admin panel sends this key in the "X-Admin-Key" header.
# -------------------------------------------------------------------
ADMIN_API_KEY = "admin-secret-key"


def require_admin(x_admin_key: Optional[str] = Header(None)) -> bool:
    """
    Validate the admin API key from the X-Admin-Key header.

    Raises 403 if the key is missing or incorrect.
    For the POC this is a single shared secret — production should use
    proper admin authentication and authorization.
    """
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return True


# -------------------------------------------------------------------
# Request/Response Models
# -------------------------------------------------------------------
class RegisterOptionsRequest(BaseModel):
    employee_id: str
    location: str
    company_email: str
    invitation_token: str


class RegisterVerifyRequest(BaseModel):
    employee_id: str
    credential: dict


class AuthOptionsRequest(BaseModel):
    employee_id: Optional[str] = None


class AuthVerifyRequest(BaseModel):
    credential: dict


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    refresh_token_expiry: str
    employee_id: str


class DeviceInfoResponse(BaseModel):
    employee_id: str
    location: str
    company_email: str
    credential_id: Optional[str]
    registered_at: Optional[str]
    last_login: Optional[str]
    refresh_token_expiry: Optional[str]
    status: str


class AdminRevokeRequest(BaseModel):
    employee_id: str


class AdminGenerateTokenRequest(BaseModel):
    employee_id: str


class AdminRevokeTokenRequest(BaseModel):
    employee_id: str


class AdminResetDeviceRequest(BaseModel):
    employee_id: str


class AdminDeviceInfo(BaseModel):
    location: str
    employee_id: str
    company_email: str
    is_registered: bool
    credential_id: Optional[str]
    registered_at: Optional[str]
    last_login: Optional[str]
    refresh_token_expiry: Optional[str]
    invitation_token: Optional[str]
    invitation_token_expiry: Optional[str]
    invitation_token_used: bool
    has_active_session: bool
    status: str


# -------------------------------------------------------------------
# Helper: Extract device from Authorization header
# -------------------------------------------------------------------
def get_current_device(authorization: Optional[str] = Header(None)) -> Optional[DeviceRecord]:
    """Extract and validate the device from the Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization.split(" ")[1]
    payload = validate_token(token, expected_type="access")
    if not payload:
        return None

    employee_id = payload.get("sub")
    return DEVICE_TABLE.get(employee_id)


# -------------------------------------------------------------------
# POST /register/options — Generate WebAuthn registration options
# -------------------------------------------------------------------
@app.post("/register/options")
async def register_options(request: RegisterOptionsRequest):
    """
    Validate the invitation token, then generate WebAuthn registration options.

    Onboarding flow (no username/password):
    - Employee enters Location, Employee ID, Company Email, and Invitation Token
    - Server confirms the employee exists and the details match the record
    - Server validates the invitation token (issued, unused, unexpired, matching)
    - Only then are registration options returned

    What happens next:
    - Frontend receives these options
    - Frontend calls navigator.credentials.create(options)
    - Browser prompts user for biometric/PIN
    - Authenticator generates a NEW keypair:
      * Private key → stays in Secure Enclave (NEVER leaves device)
      * Public key → included in the response sent back to server
    - Frontend sends the response to /register/verify
    """
    device = DEVICE_TABLE.get(request.employee_id)
    if not device:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired invitation token. Please contact your administrator.",
        )

    # Confirm the supplied employee details match the record (defense in depth)
    if (
        device.location != request.location
        or device.company_email != request.company_email
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired invitation token. Please contact your administrator.",
        )

    # Validate the invitation token (issued, unused, unexpired, matching)
    reason = validate_invitation_token(device, request.invitation_token)
    if reason is not None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired invitation token. Please contact your administrator.",
        )

    options = generate_registration_options(request.employee_id)
    return options


# -------------------------------------------------------------------
# POST /register/verify — Verify registration and store credential
# -------------------------------------------------------------------
@app.post("/register/verify", response_model=TokenResponse)
async def register_verify(request: RegisterVerifyRequest):
    """
    Verify the WebAuthn registration response and store the credential.

    What happens:
    1. Receive the attestation response from navigator.credentials.create()
    2. Decode and verify the attestation object
    3. Extract the credential_id and public_key
    4. REPLACE any existing credential for this employee
       → This is the device replacement mechanism!
       → Old phone's passkey immediately becomes invalid
    5. Revoke the previous refresh token (old device session ends)
    6. Consume the invitation token (one-time use — auto-deleted)
    7. Issue access token + refresh token

    Device Replacement Logic:
    - We overwrite credential_id and public_key with the NEW device's values
    - We issue a brand-new refresh token, discarding the old one
    - Old device still has its old private key in Secure Enclave
    - When old device tries to authenticate, it signs with old private key
    - Server verifies with NEW public key → signature FAILS
    - Old device's old refresh token no longer matches → refresh FAILS
    - Old device is automatically rejected — no manual logout needed!
    """
    device = DEVICE_TABLE.get(request.employee_id)
    if not device:
        raise HTTPException(status_code=404, detail="Employee not found")

    # Re-validate the invitation token at verify time so a token cannot be
    # consumed unless it is still valid (it may have expired or been revoked
    # between the options and verify calls).
    if validate_invitation_token(device, device.invitation_token or "") is not None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired invitation token. Please contact your administrator.",
        )

    # Verify the registration response
    result = verify_registration(request.credential)
    if not result:
        raise HTTPException(status_code=400, detail="Registration verification failed")

    # Store the new credential — REPLACING any existing one.
    # Issuing a new refresh token here automatically revokes the previous
    # device's session (its old refresh token no longer matches the record).
    now = datetime.now(timezone.utc)
    refresh_token, refresh_expiry = create_refresh_token(result["employee_id"])
    access_token = create_access_token(result["employee_id"])

    # Update the device record with the new credential (device replacement)
    device.credential_id = result["credential_id"]
    device.public_key = result["public_key"]
    device.registered_at = now
    device.last_login = now
    device.refresh_token = refresh_token
    device.refresh_token_expiry = refresh_expiry
    device.status = "active"

    # Consume the one-time invitation token (auto-deleted per spec)
    consume_invitation_token(device)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        refresh_token_expiry=refresh_expiry.isoformat(),
        employee_id=result["employee_id"],
    )


# -------------------------------------------------------------------
# POST /auth/options — Generate authentication options
# -------------------------------------------------------------------
@app.post("/auth/options")
async def auth_options(request: AuthOptionsRequest):
    """
    Generate WebAuthn authentication options for the browser.

    This is used when:
    - App starts and refresh token is missing/expired
    - But the device might still have a valid passkey in Secure Enclave

    Flow:
    1. Server checks if credential_id exists for this employee_id
    2. If yes → return options with allowCredentials pointing to that credential
    3. Browser calls navigator.credentials.get(options)
    4. If the passkey exists on THIS device → biometric prompt → signed challenge
    5. If the passkey does NOT exist (wrong device) → browser rejects silently

    For discoverable credentials (passkeys), we can also return options
    without specifying allowCredentials — the browser will check all available passkeys.
    """
    # If employee_id is provided, look up their specific credential
    if request.employee_id:
        device = DEVICE_TABLE.get(request.employee_id)
        if not device or not device.credential_id:
            raise HTTPException(
                status_code=404,
                detail="No registered credential found for this device"
            )
        options = generate_authentication_options(
            request.employee_id, device.credential_id
        )
        return options

    # If no employee_id, generate options for discoverable credentials
    # This allows the browser to find any passkey it has for this RP
    import secrets
    from services.webauthn_service import _base64url_encode, RP_ID

    challenge = secrets.token_bytes(32)
    challenge_b64 = _base64url_encode(challenge)

    # Store challenge with empty employee_id — we'll look it up after verification
    from services.webauthn_service import _active_challenges
    _active_challenges[challenge_b64] = ""

    return {
        "challenge": challenge_b64,
        "timeout": 60000,
        "rpId": RP_ID,
        "userVerification": "required",
        "allowCredentials": [],  # Empty = discoverable credential mode
    }


# -------------------------------------------------------------------
# POST /auth/verify — Verify authentication response
# -------------------------------------------------------------------
@app.post("/auth/verify", response_model=TokenResponse)
async def auth_verify(request: AuthVerifyRequest):
    """
    Verify the WebAuthn authentication response.

    What happens:
    1. Receive the assertion response from navigator.credentials.get()
    2. Find which employee this credential belongs to
    3. Verify the signature using the STORED public key
    4. If signature is valid → same device that registered → issue tokens
    5. If signature is INVALID → different device or credential was replaced → REJECT

    Why rejected credentials mean device replacement:
    - Phone A registers → stores public_key_A on server
    - Phone B registers same employee → stores public_key_B (REPLACES A)
    - Phone A tries to authenticate → signs with private_key_A
    - Server verifies with public_key_B → FAILS!
    - Result: Phone A gets "device replaced" error
    """
    credential_id = request.credential.get("id", "")

    # Find which device this credential belongs to
    device = None
    for d in DEVICE_TABLE.values():
        if d.credential_id == credential_id:
            device = d
            break

    if not device:
        raise HTTPException(
            status_code=401,
            detail="device_replaced"
        )

    # Verify the authentication response using the stored public key.
    # NOTE: verify_authentication returns the employee_id associated with the
    # challenge on success, or None on failure. In discoverable-credential mode
    # that employee_id may be an empty string (""), which is falsy — so we must
    # check `is None` here, NOT `if not result`. Using `if not result` would
    # wrongly reject a VALID discoverable passkey sign-in as "device_replaced".
    result = verify_authentication(request.credential, device.public_key)
    if result is None:
        raise HTTPException(
            status_code=401,
            detail="device_replaced"
        )

    # Authentication successful — issue new tokens
    now = datetime.now(timezone.utc)
    refresh_token, refresh_expiry = create_refresh_token(device.employee_id)
    access_token = create_access_token(device.employee_id)

    # Update device record
    device.last_login = now
    device.refresh_token = refresh_token
    device.refresh_token_expiry = refresh_expiry

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        refresh_token_expiry=refresh_expiry.isoformat(),
        employee_id=device.employee_id,
    )


# -------------------------------------------------------------------
# POST /token/refresh — Validate refresh token and issue new access token
# -------------------------------------------------------------------
@app.post("/token/refresh", response_model=TokenResponse)
async def token_refresh(request: TokenRefreshRequest):
    """
    Validate a refresh token and issue a new access token.

    This is the FIRST thing the app tries on startup:
    1. App has a refresh token stored in localStorage
    2. App sends it to this endpoint
    3. If valid AND matches the stored token → issue new access token
    4. If invalid OR doesn't match → reject (force re-authentication)

    Why matching matters for device replacement:
    - When Phone B registers, it gets a NEW refresh token
    - The old refresh token (from Phone A) is no longer stored in the device record
    - Phone A's refresh token doesn't match → rejected
    - Phone A must attempt passkey authentication → also fails (key replaced)
    - Result: Phone A is cleanly logged out
    """
    payload = validate_token(request.refresh_token, expected_type="refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    employee_id = payload.get("sub")
    device = DEVICE_TABLE.get(employee_id)

    if not device:
        raise HTTPException(status_code=401, detail="Device not found")

    # Verify this refresh token matches the one stored for this device
    # This ensures old refresh tokens (from replaced devices) are rejected
    if device.refresh_token != request.refresh_token:
        raise HTTPException(status_code=401, detail="Token has been revoked")

    # Issue a new access token (refresh token stays the same)
    access_token = create_access_token(employee_id)
    device.last_login = datetime.now(timezone.utc)

    return TokenResponse(
        access_token=access_token,
        refresh_token=device.refresh_token,
        refresh_token_expiry=device.refresh_token_expiry.isoformat(),
        employee_id=employee_id,
    )


# -------------------------------------------------------------------
# POST /logout — Invalidate refresh token
# -------------------------------------------------------------------
@app.post("/logout")
async def logout(request: TokenRefreshRequest):
    """
    Invalidate the refresh token for a device.

    Clears the stored refresh token so it can no longer be used.
    The passkey remains valid — only the session is ended.
    """
    payload = validate_token(request.refresh_token, expected_type="refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    employee_id = payload.get("sub")
    device = DEVICE_TABLE.get(employee_id)

    if device:
        device.refresh_token = None
        device.refresh_token_expiry = None

    return {"message": "Logged out successfully"}


# -------------------------------------------------------------------
# GET /device — Return current device registration information
# -------------------------------------------------------------------
@app.get("/device", response_model=DeviceInfoResponse)
async def get_device_info(device: Optional[DeviceRecord] = Depends(get_current_device)):
    """
    Return the current device's registration information.

    Requires a valid access token in the Authorization header.
    """
    if not device:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return DeviceInfoResponse(
        employee_id=device.employee_id,
        location=device.location,
        company_email=device.company_email,
        credential_id=device.credential_id,
        registered_at=device.registered_at.isoformat() if device.registered_at else None,
        last_login=device.last_login.isoformat() if device.last_login else None,
        refresh_token_expiry=device.refresh_token_expiry.isoformat() if device.refresh_token_expiry else None,
        status=device.status,
    )


# -------------------------------------------------------------------
# GET /admin/devices — List all devices (admin only)
# -------------------------------------------------------------------
# -------------------------------------------------------------------
# Helper: Build an AdminDeviceInfo from a DeviceRecord
# -------------------------------------------------------------------
def _build_admin_device_info(device: DeviceRecord) -> AdminDeviceInfo:
    """Map an internal DeviceRecord to the admin-facing response model."""
    return AdminDeviceInfo(
        location=device.location,
        employee_id=device.employee_id,
        company_email=device.company_email,
        is_registered=device.credential_id is not None,
        credential_id=device.credential_id,
        registered_at=device.registered_at.isoformat() if device.registered_at else None,
        last_login=device.last_login.isoformat() if device.last_login else None,
        refresh_token_expiry=device.refresh_token_expiry.isoformat() if device.refresh_token_expiry else None,
        invitation_token=device.invitation_token,
        invitation_token_expiry=device.invitation_token_expiry.isoformat() if device.invitation_token_expiry else None,
        invitation_token_used=device.invitation_token_used,
        has_active_session=device.refresh_token is not None,
        status=device.status,
    )


@app.get("/admin/devices", response_model=list[AdminDeviceInfo])
async def admin_list_devices(_: bool = Depends(require_admin)):
    """
    Return all employee/device records and their registration/session status.

    Used by the admin panel to display every employee, whether they have
    a registered passkey, their current session status, and any outstanding
    invitation token.

    Requires the X-Admin-Key header.
    """
    return [_build_admin_device_info(device) for device in DEVICE_TABLE.values()]


# -------------------------------------------------------------------
# POST /admin/revoke — Force-revoke a device (admin only)
# -------------------------------------------------------------------
@app.post("/admin/revoke", response_model=AdminDeviceInfo)
async def admin_revoke_device(
    request: AdminRevokeRequest,
    _: bool = Depends(require_admin),
):
    """
    Administratively revoke a device's registration and session.

    What this does:
    1. Clears credential_id + public_key → passkey authentication will FAIL
       (the old phone's credential no longer matches anything on the server)
    2. Clears refresh_token + expiry → token refresh will FAIL
       (the old phone's stored refresh token no longer matches)
    3. Sets status to "revoked"

    Result — the targeted device is signed out on its next app open:
    - /token/refresh → stored refresh_token is None → rejected (401)
    - /auth/verify   → no credential_id to match → rejected (device_replaced)
    The employee must onboard again with a new invitation token to use the app.

    This is the administrator equivalent of the automatic revocation that
    happens when a new device registers for the same employee.

    Requires the X-Admin-Key header.
    """
    device = DEVICE_TABLE.get(request.employee_id)
    if not device:
        raise HTTPException(status_code=404, detail="Employee not found")

    # Wipe all auth-critical fields so BOTH refresh and passkey auth fail
    device.credential_id = None
    device.public_key = None
    device.refresh_token = None
    device.refresh_token_expiry = None
    device.registered_at = None
    device.status = "revoked"

    return _build_admin_device_info(device)


# -------------------------------------------------------------------
# POST /admin/generate-token — Issue an invitation token (admin only)
# -------------------------------------------------------------------
@app.post("/admin/generate-token", response_model=AdminDeviceInfo)
async def admin_generate_token(
    request: AdminGenerateTokenRequest,
    _: bool = Depends(require_admin),
):
    """
    Generate a new invitation token for an employee.

    The token is created on demand, is single-use, and expires after a
    configurable window (default 24 hours). Generating a new token overwrites
    any previously issued-but-unused token for the employee.

    Requires the X-Admin-Key header.
    """
    device = DEVICE_TABLE.get(request.employee_id)
    if not device:
        raise HTTPException(status_code=404, detail="Employee not found")

    issue_invitation_token(device)
    return _build_admin_device_info(device)


# -------------------------------------------------------------------
# POST /admin/revoke-token — Revoke an unused invitation token (admin only)
# -------------------------------------------------------------------
@app.post("/admin/revoke-token", response_model=AdminDeviceInfo)
async def admin_revoke_token(
    request: AdminRevokeTokenRequest,
    _: bool = Depends(require_admin),
):
    """
    Revoke an employee's outstanding invitation token before it is used.

    Clears the token and its expiry so it can no longer be validated. Does NOT
    affect an already-registered device or its session — it only cancels a
    pending onboarding token.

    Requires the X-Admin-Key header.
    """
    device = DEVICE_TABLE.get(request.employee_id)
    if not device:
        raise HTTPException(status_code=404, detail="Employee not found")

    revoke_invitation_token(device)
    return _build_admin_device_info(device)


# -------------------------------------------------------------------
# POST /admin/reset-device — Reset a device registration (admin only)
# -------------------------------------------------------------------
@app.post("/admin/reset-device", response_model=AdminDeviceInfo)
async def admin_reset_device(
    request: AdminResetDeviceRequest,
    _: bool = Depends(require_admin),
):
    """
    Reset an employee's device registration.

    What this does:
    1. Removes credential_id + public_key → passkey no longer recognized
    2. Removes refresh_token + expiry → session invalid
    3. Clears registered_at → shows as never registered
    4. Sets status to "not_registered"

    Unlike /admin/revoke which sets status="revoked", reset returns the
    employee to a clean state as if they never registered. They can then
    onboard a device again with a new invitation token.

    Requires the X-Admin-Key header.
    """
    device = DEVICE_TABLE.get(request.employee_id)
    if not device:
        raise HTTPException(status_code=404, detail="Employee not found")

    # Clear all registration and session data
    device.credential_id = None
    device.public_key = None
    device.refresh_token = None
    device.refresh_token_expiry = None
    device.registered_at = None
    device.last_login = None
    device.status = "not_registered"

    return _build_admin_device_info(device)


# -------------------------------------------------------------------
# GET / — Health check
# -------------------------------------------------------------------
@app.get("/")
async def root():
    return {
        "service": "WebAuthn Device Registration POC",
        "status": "running",
        "devices": len(DEVICE_TABLE),
    }
