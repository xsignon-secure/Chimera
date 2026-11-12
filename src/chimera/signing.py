"""HMAC request signing shared by the honeypot (sender) and responder (receiver)."""

from __future__ import annotations

import hashlib
import hmac
import time

SIG_HEADER = "X-Chimera-Signature"
TS_HEADER = "X-Chimera-Timestamp"
MAX_SKEW_SECONDS = 300


def sign(secret: str, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {SIG_HEADER: f"sha256={mac}", TS_HEADER: ts}


def verify(secret: str, body: bytes, signature: str | None, timestamp: str | None, now: float | None = None) -> bool:
    if not secret or not signature or not timestamp:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((time.time() if now is None else now) - ts) > MAX_SKEW_SECONDS:
        return False
    expected = sign(secret, body, ts)[SIG_HEADER]
    return hmac.compare_digest(expected, signature)
