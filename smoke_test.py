"""
Smoke test for the invitation-token refactor.

Verifies (without a real browser/passkey):
- Health check
- Admin can generate an invitation token
- /register/options accepts a VALID invitation token (returns WebAuthn options)
- /register/options REJECTS an invalid token with the friendly 400 message
- Admin can revoke an invitation token
- /admin/devices returns the new employee-centric fields

NOTE: Full registration (/register/verify) needs a real authenticator, so we
only validate the invitation-token gating here.
"""
import requests

BASE = "http://localhost:8000"
ADMIN = {"X-Admin-Key": "admin-secret-key"}
EMP = "EMP001"


def check(label, condition):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    return condition


def main():
    all_ok = True

    # 1. Health check
    r = requests.get(f"{BASE}/")
    all_ok &= check("Health check returns 200 + 10 devices",
                    r.status_code == 200 and r.json().get("devices") == 10)

    # 2. Admin generates an invitation token for EMP001
    r = requests.post(f"{BASE}/admin/generate-token",
                      json={"employee_id": EMP}, headers=ADMIN)
    token = r.json().get("invitation_token") if r.status_code == 200 else None
    all_ok &= check("Admin generate-token returns INV- token",
                    r.status_code == 200 and token and token.startswith("INV-"))

    # 3. /register/options with the VALID token → WebAuthn options (has challenge)
    r = requests.post(f"{BASE}/register/options", json={
        "employee_id": EMP,
        "location": "Clinic 1",
        "company_email": "alison@clinic.com",
        "invitation_token": token,
    })
    all_ok &= check("register/options accepts valid token (returns challenge)",
                    r.status_code == 200 and "challenge" in r.json())

    # 4. /register/options with an INVALID token → 400 + friendly message
    r = requests.post(f"{BASE}/register/options", json={
        "employee_id": EMP,
        "location": "Clinic 1",
        "company_email": "alison@clinic.com",
        "invitation_token": "INV-0000-0000-0000",
    })
    all_ok &= check("register/options rejects invalid token (400 + message)",
                    r.status_code == 400 and "invitation token" in r.json().get("detail", "").lower())

    # 5. Admin revokes the invitation token
    r = requests.post(f"{BASE}/admin/revoke-token",
                      json={"employee_id": EMP}, headers=ADMIN)
    all_ok &= check("Admin revoke-token clears the token",
                    r.status_code == 200 and r.json().get("invitation_token") is None)

    # 6. After revoke, /register/options should now reject (no token issued)
    r = requests.post(f"{BASE}/register/options", json={
        "employee_id": EMP,
        "location": "Clinic 1",
        "company_email": "alison@clinic.com",
        "invitation_token": token,
    })
    all_ok &= check("register/options rejects revoked token (400)",
                    r.status_code == 400)

    # 7. /admin/devices returns new employee-centric fields
    r = requests.get(f"{BASE}/admin/devices", headers=ADMIN)
    first = r.json()[0] if r.status_code == 200 and r.json() else {}
    all_ok &= check("admin/devices has location/employee_id/company_email fields",
                    all(k in first for k in ("location", "employee_id", "company_email",
                                             "invitation_token_used", "is_registered")))

    # 8. Admin auth is enforced (wrong key → 403)
    r = requests.get(f"{BASE}/admin/devices", headers={"X-Admin-Key": "wrong"})
    all_ok &= check("admin/devices rejects wrong admin key (403)", r.status_code == 403)

    print("\n" + ("ALL SMOKE TESTS PASSED ✅" if all_ok else "SOME TESTS FAILED ❌"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
