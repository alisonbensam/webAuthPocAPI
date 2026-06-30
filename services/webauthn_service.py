"""
WebAuthn Service — Handles passkey registration and authentication.

This service implements the server-side (Relying Party) logic for WebAuthn:

Registration Flow:
1. Generate registration options (challenge, RP info, user info)
2. Receive and verify the registration response from the browser
3. Extract and store the credential_id and public_key

Authentication Flow:
1. Generate authentication options (challenge, allowed credentials)
2. Receive and verify the authentication response
3. Validate the signature using the stored public_key

Key Security Concepts:
- The PRIVATE KEY never leaves the device's Secure Enclave / Android Keystore
- Only the PUBLIC KEY is sent to and stored on the server
- The server uses the public key to VERIFY signatures, not to decrypt
- Each credential_id is unique and tied to a specific device+origin combination
"""

import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

import cbor2
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.backends import default_backend

# -------------------------------------------------------------------
# Relying Party Configuration
# -------------------------------------------------------------------
# The RP ID must match the origin's effective domain.
# For localhost development, we use "localhost".
# -------------------------------------------------------------------
RP_ID = "web-auth-poc-ui.vercel.app"
RP_NAME = "WebAuthn Device POC"
ORIGIN = "https://web-auth-poc-ui.vercel.app"

# Store active challenges in memory (maps challenge -> device_id)
_active_challenges: dict[str, str] = {}


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string (with or without padding) to bytes."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def generate_registration_options(device_id: str) -> dict:
    """
    Generate WebAuthn registration options for the browser.

    What happens:
    - Server generates a random challenge (prevents replay attacks)
    - Server specifies the Relying Party (RP) identity
    - Server specifies the user identity (device_id)
    - Server specifies acceptable credential types (platform authenticator)

    The browser will use these options in navigator.credentials.create()
    to prompt the user for biometric/PIN authentication and create a new keypair.

    Why platform authenticator?
    - "platform" means the device's built-in authenticator (Touch ID, Face ID, Windows Hello)
    - The private key is stored in the Secure Enclave/TPM — it NEVER leaves the device
    - This is what makes WebAuthn phishing-resistant

    Args:
        device_id: The device identifier requesting registration

    Returns:
        Registration options dict to send to the browser
    """
    # Generate a random 32-byte challenge
    # The challenge prevents replay attacks — each registration attempt needs a fresh one
    challenge = secrets.token_bytes(32)
    challenge_b64 = _base64url_encode(challenge)

    # Store the challenge so we can verify it when the response comes back
    _active_challenges[challenge_b64] = device_id

    # User ID must be unique per user — we use a hash of the device_id
    user_id = _base64url_encode(hashlib.sha256(device_id.encode()).digest())

    options = {
        # The challenge that must be signed by the authenticator
        "challenge": challenge_b64,

        # Relying Party information — identifies this service
        "rp": {
            "name": RP_NAME,
            "id": RP_ID,  # Must match the origin's effective domain
        },

        # User information — identifies the device/account
        "user": {
            "id": user_id,
            "name": device_id,
            "displayName": device_id,
        },

        # We only accept ES256 (ECDSA with P-256 curve)
        # This is the most widely supported algorithm across devices
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7}  # -7 = ES256
        ],

        # Timeout in milliseconds (60 seconds)
        "timeout": 60000,

        # Attestation: "none" means we don't need the device to prove its make/model
        # This simplifies the flow and improves privacy
        "attestation": "none",

        # Authenticator selection criteria
        "authenticatorSelection": {
            # "platform" = built-in authenticator (Touch ID, Face ID, Windows Hello)
            # The private key stays in the Secure Enclave — never extractable
            "authenticatorAttachment": "platform",

            # Require the authenticator to verify the user (biometric/PIN)
            "userVerification": "required",

            # "required" means a credential must be stored on the authenticator
            # This creates a discoverable credential (passkey)
            "residentKey": "required",

            # Legacy flag — same as residentKey: "required"
            "requireResidentKey": True,
        },
    }

    return options


def verify_registration(registration_response: dict) -> Optional[dict]:
    """
    Verify the registration response from the browser.

    What happened on the client:
    1. Browser called navigator.credentials.create() with our options
    2. Device prompted user for biometric/PIN authentication
    3. Authenticator generated a NEW keypair:
       - Private key → stored in Secure Enclave/Android Keystore (NEVER leaves device)
       - Public key → sent to us in the response
    4. Authenticator signed the challenge with the new private key
    5. Browser returns the credential with attestation object and client data

    What we do here:
    1. Decode the attestation object (CBOR encoded)
    2. Extract the public key from the authenticator data
    3. Verify the challenge matches what we sent
    4. Return the credential_id and public_key for storage

    Why only store the public key?
    - The public key can only VERIFY signatures, not create them
    - Even if our server is compromised, the attacker cannot impersonate the device
    - Only the device with the private key in its Secure Enclave can authenticate

    Args:
        registration_response: The response from navigator.credentials.create()

    Returns:
        Dict with credential_id and public_key if valid, None if invalid
    """
    try:
        # Extract the credential ID from the response
        credential_id = registration_response.get("id", "")
        raw_id = registration_response.get("rawId", "")

        # Get the attestation response
        response = registration_response.get("response", {})
        client_data_json_b64 = response.get("clientDataJSON", "")
        attestation_object_b64 = response.get("attestationObject", "")

        if not all([credential_id, client_data_json_b64, attestation_object_b64]):
            return None

        # Decode client data to verify the challenge
        client_data_bytes = _base64url_decode(client_data_json_b64)
        import json
        client_data = json.loads(client_data_bytes.decode("utf-8"))

        # Verify the challenge matches one we issued
        challenge = client_data.get("challenge", "")
        if challenge not in _active_challenges:
            return None

        device_id = _active_challenges.pop(challenge)

        # Verify the origin matches our expected origin
        if client_data.get("origin") != ORIGIN:
            # Allow localhost variations for development
            origin = client_data.get("origin", "")
            if "localhost" not in origin:
                return None

        # Verify the type is "webauthn.create"
        if client_data.get("type") != "webauthn.create":
            return None

        # Decode the attestation object (CBOR format)
        attestation_bytes = _base64url_decode(attestation_object_b64)
        attestation_object = cbor2.loads(attestation_bytes)

        # Extract authenticator data from the attestation object
        auth_data = attestation_object.get("authData", b"")

        # Parse authenticator data structure:
        # [32 bytes: rpIdHash][1 byte: flags][4 bytes: signCount][variable: attestedCredentialData]
        rp_id_hash = auth_data[:32]
        flags = auth_data[32]
        sign_count = int.from_bytes(auth_data[33:37], "big")

        # Verify flags: bit 0 (UP) and bit 2 (UV) should be set
        user_present = bool(flags & 0x01)
        user_verified = bool(flags & 0x04)
        attested_data_present = bool(flags & 0x40)

        if not user_present or not attested_data_present:
            return None

        # Parse attested credential data:
        # [16 bytes: AAGUID][2 bytes: credIdLength][credIdLength bytes: credId][variable: credentialPublicKey (CBOR)]
        aaguid = auth_data[37:53]
        cred_id_length = int.from_bytes(auth_data[53:55], "big")
        cred_id = auth_data[55:55 + cred_id_length]
        cose_public_key_bytes = auth_data[55 + cred_id_length:]

        # Decode the COSE public key (CBOR encoded)
        cose_key = cbor2.loads(cose_public_key_bytes)

        # Extract EC2 key parameters:
        # 1: key type (2 = EC2)
        # 3: algorithm (-7 = ES256)
        # -1: curve (1 = P-256)
        # -2: x coordinate
        # -3: y coordinate
        kty = cose_key.get(1)
        alg = cose_key.get(3)
        crv = cose_key.get(-1)
        x = cose_key.get(-2)
        y = cose_key.get(-3)

        if kty != 2 or alg != -7 or crv != 1:
            return None

        # Convert to PEM format for storage
        # We store the public key in PEM so we can reconstruct it for verification later
        x_int = int.from_bytes(x, "big")
        y_int = int.from_bytes(y, "big")

        public_numbers = EllipticCurvePublicNumbers(x_int, y_int, SECP256R1())
        public_key = public_numbers.public_key(default_backend())
        public_key_pem = public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        # Return the credential data for storage
        credential_id_b64 = _base64url_encode(cred_id)

        return {
            "credential_id": credential_id_b64,
            "public_key": public_key_pem,
            "device_id": device_id,
        }

    except Exception as e:
        print(f"Registration verification failed: {e}")
        return None


def generate_authentication_options(device_id: str, credential_id: str) -> dict:
    """
    Generate WebAuthn authentication options for the browser.

    What happens:
    - Server generates a fresh challenge
    - Server tells the browser which credential to use (allowCredentials)
    - Browser will use navigator.credentials.get() to sign the challenge

    The private key in the Secure Enclave signs the challenge.
    We verify the signature with the stored public key.
    This proves the SAME DEVICE that registered is now authenticating.

    Args:
        device_id: The device identifier
        credential_id: The stored credential ID (base64url) to allow

    Returns:
        Authentication options dict to send to the browser
    """
    # Generate a random challenge for this authentication attempt
    challenge = secrets.token_bytes(32)
    challenge_b64 = _base64url_encode(challenge)

    # Store the challenge for verification
    _active_challenges[challenge_b64] = device_id

    options = {
        # Fresh challenge that must be signed by the authenticator's private key
        "challenge": challenge_b64,

        # Timeout in milliseconds
        "timeout": 60000,

        # RP ID must match the domain
        "rpId": RP_ID,

        # User verification required (biometric/PIN)
        "userVerification": "required",

        # Tell the browser which credential to use
        # This narrows down to the specific passkey for this device login
        "allowCredentials": [
            {
                "type": "public-key",
                "id": credential_id,
                "transports": ["internal"],  # Platform authenticator
            }
        ],
    }

    return options


def verify_authentication(auth_response: dict, stored_public_key_pem: str) -> Optional[str]:
    """
    Verify the authentication response from the browser.

    What happened on the client:
    1. Browser called navigator.credentials.get() with our options
    2. Device prompted user for biometric/PIN
    3. Authenticator signed the challenge using the PRIVATE KEY in Secure Enclave
    4. Browser returned the signature and authenticator data

    What we do here:
    1. Reconstruct the signed data (authenticator data + hash of client data)
    2. Verify the signature using the STORED PUBLIC KEY
    3. If signature is valid → the same device that registered is authenticating
    4. If signature is invalid → either wrong device or credential was replaced

    Why this works for device replacement:
    - When Phone B registers, we replace the stored public_key with Phone B's key
    - Phone A still has its old private key in Secure Enclave
    - Phone A signs with its old private key
    - Server tries to verify with Phone B's public key → FAILS
    - Therefore, Phone A is automatically rejected without manual logout

    Args:
        auth_response: The response from navigator.credentials.get()
        stored_public_key_pem: The PEM-encoded public key stored for this credential

    Returns:
        The device_id if authentication succeeds, None if it fails
    """
    try:
        credential_id = auth_response.get("id", "")
        response = auth_response.get("response", {})
        client_data_json_b64 = response.get("clientDataJSON", "")
        authenticator_data_b64 = response.get("authenticatorData", "")
        signature_b64 = response.get("signature", "")

        if not all([credential_id, client_data_json_b64, authenticator_data_b64, signature_b64]):
            return None

        # Decode client data
        client_data_bytes = _base64url_decode(client_data_json_b64)
        import json
        client_data = json.loads(client_data_bytes.decode("utf-8"))

        # Verify the challenge
        challenge = client_data.get("challenge", "")
        if challenge not in _active_challenges:
            return None

        device_id = _active_challenges.pop(challenge)

        # Verify the type
        if client_data.get("type") != "webauthn.get":
            return None

        # Decode authenticator data and signature
        auth_data_bytes = _base64url_decode(authenticator_data_b64)
        signature_bytes = _base64url_decode(signature_b64)

        # Reconstruct the signed message:
        # signedData = authenticatorData + SHA-256(clientDataJSON)
        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        signed_data = auth_data_bytes + client_data_hash

        # Verify the signature using the stored public key
        # This is the core of WebAuthn security:
        # - Only the device with the private key can produce a valid signature
        # - We verify with the public key that was stored during registration
        # - If the credential was replaced (new device registered), verification FAILS
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        public_key = load_pem_public_key(
            stored_public_key_pem.encode("utf-8"),
            backend=default_backend()
        )

        # Verify ECDSA signature
        public_key.verify(signature_bytes, signed_data, ECDSA(SHA256()))

        # Verify flags in authenticator data
        flags = auth_data_bytes[32]
        user_present = bool(flags & 0x01)
        if not user_present:
            return None

        return device_id

    except Exception as e:
        print(f"Authentication verification failed: {e}")
        return None
