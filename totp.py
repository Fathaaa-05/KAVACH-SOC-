"""Print the current MFA code for a user (demo helper):  python -m app.totp admin"""
import sys

import pyotp

from . import db

user = sys.argv[1] if len(sys.argv) > 1 else "admin"
row = db.q1("SELECT mfa_secret, mfa_enabled FROM users WHERE username=?", (user,))
if not row or not row["mfa_secret"]:
    sys.exit(f"{user} has no MFA secret")
print(pyotp.TOTP(row["mfa_secret"]).now())
