"""Password hashing, signed session cookies, and login throttling.

Stdlib only: scrypt from hashlib, HMAC-signed cookie. No JWT library, nothing
to keep patched.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict

COOKIE_NAME = "smartdns_dash"

# scrypt parameters. n=16384 keeps a login under ~100ms on a modest VM.
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N,
                        r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n),
                            r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(secret_key: str, username: str, hours: int,
               role: str = "operator") -> str:
    """Signed session token.

    The role travels inside the signed payload rather than being looked up per
    request, so a viewer cannot become an operator by editing a cookie - the
    signature covers it.
    """
    payload = {
        "u": username,
        "r": role,
        "exp": int(time.time()) + hours * 3600,
        "jti": secrets.token_hex(8),
    }
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret_key.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64u(sig)}"


def read_token(secret_key: str, token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    body, _, sig = token.partition(".")
    expected = hmac.new(secret_key.encode(), body.encode(), hashlib.sha256).digest()
    try:
        given = _unb64u(sig)
    except Exception:
        return None
    if not hmac.compare_digest(expected, given):
        return None
    try:
        payload = json.loads(_unb64u(body))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("exp", 0) < time.time():
        return None
    return payload


class LoginThrottle:
    """Per-source-IP failed-login counter with a sliding window."""

    def __init__(self, max_attempts: int = 5, window_s: int = 900,
                 lockout_s: int = 900):
        self.max_attempts = max_attempts
        self.window_s = window_s
        self.lockout_s = lockout_s
        self._fails: dict[str, list] = defaultdict(list)

    def _prune(self, ip: str) -> None:
        cutoff = time.time() - self.window_s
        self._fails[ip] = [t for t in self._fails[ip] if t > cutoff]

    def locked_for(self, ip: str) -> float:
        """Seconds remaining in a lockout, or 0."""
        self._prune(ip)
        fails = self._fails[ip]
        if len(fails) < self.max_attempts:
            return 0.0
        remaining = (fails[-1] + self.lockout_s) - time.time()
        return max(0.0, remaining)

    def record_failure(self, ip: str) -> None:
        self._prune(ip)
        self._fails[ip].append(time.time())

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)


def constant_time_user_check(given: str, expected: str) -> bool:
    return hmac.compare_digest(given.encode(), expected.encode())


def new_secret_key() -> str:
    return secrets.token_hex(32)


def secure_cookie_kwargs(exposed: bool, https: bool,
                         path: str = "/") -> dict:
    """Cookie flags.

    `secure` is set when the connection the browser sees is HTTPS - either we
    terminate TLS ourselves or a trusted proxy does. Setting it on a plain-HTTP
    deployment would make the browser drop the cookie and login would fail
    silently, which is why it is not simply always on.
    """
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": bool(https),
        "path": path or "/",
    }


def csrf_token(secret_key: str, session_jti: str) -> str:
    """CSRF token bound to the session, for state-changing POSTs."""
    return _b64u(hmac.new(secret_key.encode(), ("csrf:" + session_jti).encode(),
                          hashlib.sha256).digest())


def check_csrf(secret_key: str, session_jti: str, given: str | None) -> bool:
    if not given:
        return False
    return hmac.compare_digest(csrf_token(secret_key, session_jti), given)


__all__ = [
    "COOKIE_NAME", "hash_password", "verify_password", "make_token",
    "read_token", "LoginThrottle", "constant_time_user_check",
    "new_secret_key", "secure_cookie_kwargs", "csrf_token", "check_csrf",
]
