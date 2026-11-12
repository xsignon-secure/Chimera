"""Canary watermarking: every secret the honeypot hands out is a tripwire.

Each value is derived with HMAC from a per-deployment secret, so it is unique
to the session, tool, and moment it was issued, and looks like a real secret
of its kind. Three detection paths exist:

1. **Reuse**: the value comes back inside any later MCP request (same or
   different attacker). Detected in-process by :meth:`CanaryWatermarker.scan`.
2. **Callback**: URL canaries point at the honeypot's own HTTP surface. Any
   fetch of that URL is a ``canary.triggered`` event.
3. **External**: real Canarytokens (e.g. AWS API keys from canarytokens.org,
   free) can be loaded from a file. If the attacker uses one against AWS, the
   Canarytokens service alerts you, and the registry tells you exactly which
   session stole it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import string
import struct
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from chimera.models import CanaryRecord
from chimera.store import Store

CanaryKind = Literal["aws_key", "password", "ssh_key", "vault_token", "db_url", "api_key", "callback_url", "jwt"]

_B62 = string.ascii_letters + string.digits
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


MAX_CANARIES_PER_SESSION = 120
"""Beyond this, a session gets previously issued values back (bounds registry growth)."""
INDEX_RETENTION_DAYS = 180
_PREFIX = 8


class IssuedCanary(BaseModel):
    canary_id: str
    kind: CanaryKind
    value: str
    """Primary value the attacker sees (e.g. an access key id or password)."""
    secondary: str | None = None
    """Paired value (e.g. AWS secret access key)."""
    marker: str
    """Distinctive substring used to detect reuse."""
    external: bool = False


class CanaryHit(BaseModel):
    canary_id: str
    kind: str
    session_id: str
    marker: str


class ExternalAwsToken(BaseModel):
    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"


class CanaryWatermarker:
    def __init__(self, store: Store, secret: str, public_base_url: str, external_file: Path | None = None) -> None:
        self._store = store
        self._key = secret.encode()
        self._base = public_base_url.rstrip("/")
        # marker -> canary ids (a list: an external key may be issued to several sessions)
        self._by_marker: dict[str, list[str]] = {}
        # first 8 chars of a marker -> markers; makes scanning O(len(text)), not O(#canaries)
        self._prefix: dict[str, set[str]] = {}
        self._meta: dict[str, tuple[str, str]] = {}  # canary id -> (kind, session id)
        self._external: list[ExternalAwsToken] = []
        if external_file:
            self._external = load_external_tokens(external_file)

    async def warm(self) -> None:
        """Index recently issued markers so reuse is detected across restarts."""
        cutoff = datetime.now(UTC) - timedelta(days=INDEX_RETENTION_DAYS)
        for rec in await self._store.all_canaries():
            if rec.issued_at >= cutoff:
                self._index(rec.canary_id, rec.kind, rec.session_id, _marker_for(rec.kind, rec.value))

    def _index(self, canary_id: str, kind: str, session_id: str, marker: str) -> None:
        if len(marker) < _PREFIX:
            return
        ids = self._by_marker.setdefault(marker, [])
        if canary_id not in ids:
            ids.append(canary_id)
        self._prefix.setdefault(marker[:_PREFIX], set()).add(marker)
        self._meta[canary_id] = (kind, session_id)

    # -- derivation --------------------------------------------------------
    def _digest(self, *parts: str) -> bytes:
        return hmac.new(self._key, "|".join(parts).encode(), hashlib.sha256).digest()

    @staticmethod
    def _alphabet(raw: bytes, alphabet: str, n: int) -> str:
        # Expand with SHAKE so long outputs never run out of entropy (no padding tells).
        stream = hashlib.shake_256(raw).digest(n * 2)
        return "".join(alphabet[int.from_bytes(stream[i * 2 : i * 2 + 2], "big") % len(alphabet)] for i in range(n))

    async def issue(
        self,
        kind: CanaryKind,
        *,
        session_id: str,
        source_ip: str,
        tool: str,
        context: str = "",
        cache: dict[str, Any] | None = None,
    ) -> IssuedCanary:
        """Issue a canary.

        ``cache`` is the session's persistent state. The same (kind, context)
        within one session returns the same value, as a real system would
        (reading ``~/.aws/credentials`` twice gives the same key), and a
        session can never grow the registry beyond ``MAX_CANARIES_PER_SESSION``.
        """
        key = f"{kind}|{context[:200]}"
        bucket: dict[str, Any] | None = None
        if cache is not None:
            bucket = cache.setdefault("_canaries", {})
            if key in bucket:
                return IssuedCanary.model_validate(bucket[key])
            if len(bucket) >= MAX_CANARIES_PER_SESSION:
                same_kind = [v for k, v in bucket.items() if k.startswith(kind + "|")]
                if same_kind:
                    return IssuedCanary.model_validate(same_kind[secrets.randbelow(len(same_kind))])

        nonce = secrets.token_hex(8)
        d = self._digest(kind, session_id, tool, context, nonce)
        d2 = self._digest("2", kind, session_id, tool, context, nonce)
        canary_id = "cnr_" + base64.b32encode(d[:10]).decode().lower().rstrip("=")
        secondary: str | None = None
        external = False

        if kind == "aws_key":
            ext = await self._next_external()
            if ext:
                value, secondary, external = ext.access_key_id, ext.secret_access_key, True
            else:
                value = "AKIA" + self._alphabet(d, _B32, 16)
                secondary = self._alphabet(d2 + d, _B62 + "+/", 40)
        elif kind == "password":
            words = ["Falcon", "Harbor", "Quartz", "Summit", "Cobalt", "Meridian", "Orchid", "Granite"]
            w = words[d[0] % len(words)]
            value = f"{w}{d[1] % 90 + 10}{'!@#$%&*'[d[2] % 7]}{self._alphabet(d[3:], _B62, 6)}"
        elif kind == "ssh_key":
            value = openssh_ed25519_private_key(d, comment=context.split(":")[-1][:40] or "admin@bastion")
        elif kind == "vault_token":
            value = "hvs." + self._alphabet(d + d2, _B62, 90)
        elif kind == "api_key":
            value = "sk_live_" + self._alphabet(d + d2, _B62, 40)
        elif kind == "jwt":
            header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
            payload = _b64url(
                json.dumps({"sub": context or "svc", "jti": self._alphabet(d, _B62, 16), "scope": "admin"}).encode()
            )
            value = f"{header}.{payload}.{_b64url(d2)}"
        elif kind == "db_url":
            pw = self._alphabet(d, _B62, 20)
            value = context.replace("{password}", pw) if "{password}" in context else pw
        elif kind == "callback_url":
            token = self._alphabet(d, _B62.lower()[:36], 24)
            path = context or "files"
            value = f"{self._base}/{path.strip('/')}/{token}"
        else:  # pragma: no cover - Literal guards this
            raise ValueError(kind)

        marker = _marker_for(kind, value)
        self._index(canary_id, kind, session_id, marker)
        await self._store.add_canary(
            CanaryRecord(
                canary_id=canary_id,
                kind=kind,
                value=value,
                session_id=session_id,
                source_ip=source_ip,
                tool=tool,
                external=external,
            )
        )
        issued = IssuedCanary(
            canary_id=canary_id, kind=kind, value=value, secondary=secondary, marker=marker, external=external
        )
        if bucket is not None:
            bucket[key] = issued.model_dump()
        return issued

    async def _next_external(self) -> ExternalAwsToken | None:
        if not self._external:
            return None
        used = await self._store.external_values_in_use()
        for tok in self._external:
            if tok.access_key_id not in used:
                return tok
        # Pool exhausted: rotate. Every holder is recorded; see ``hits``.
        return self._external[secrets.randbelow(len(self._external))]

    # -- detection ---------------------------------------------------------
    def hits(self, text: str, limit: int = 65_536) -> list[CanaryHit]:
        """Every issued canary whose marker appears in ``text``.

        Uses an 8-character prefix index, so cost grows with the text length,
        not with the number of canaries ever issued.
        """
        if not text or not self._prefix:
            return []
        text = text[:limit]
        found: set[str] = set()
        for i in range(len(text) - _PREFIX + 1):
            markers = self._prefix.get(text[i : i + _PREFIX])
            if markers:
                for m in markers:
                    if text.startswith(m, i):
                        found.add(m)
        out: list[CanaryHit] = []
        for m in found:
            for cid in self._by_marker.get(m, []):
                kind, sid = self._meta.get(cid, ("unknown", ""))
                out.append(CanaryHit(canary_id=cid, kind=kind, session_id=sid, marker=m))
        return sorted(out, key=lambda h: h.canary_id)

    def scan(self, text: str) -> list[str]:
        """Canary ids whose marker appears in ``text``."""
        return sorted({h.canary_id for h in self.hits(text)})

    def callback_token_to_id(self, url_path: str) -> str | None:
        token = url_path.rstrip("/").rsplit("/", 1)[-1]
        for h in self.hits(token):
            if h.kind == "callback_url":
                return h.canary_id
        return None


def _marker_for(kind: str, value: str) -> str:
    if kind == "ssh_key":
        # Line 2 of the base64 body carries the random public key; line 1 is a constant header.
        lines = [ln for ln in value.splitlines() if ln and not ln.startswith("-----")]
        return lines[1][:48] if len(lines) > 1 else value[:48]
    if kind == "jwt":
        return value.rsplit(".", 1)[-1]
    if kind == "callback_url":
        return value.rsplit("/", 1)[-1]
    if kind == "db_url":
        m = re.search(r"://[^:/@]+:([^@]+)@", value)
        return m.group(1) if m else value
    return value


# ---------------------------------------------------------------------------- OpenSSH keys
# Minimal pure-Python Ed25519 public-key derivation (RFC 8032), so canary SSH keys are
# structurally valid OpenSSH keys that parse in ssh-keygen / cryptography.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_GY = 4 * pow(5, _P - 2, _P) % _P


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    return _P - x if x % 2 else x


_G = (_recover_x(_GY), _GY, 1, _recover_x(_GY) * _GY % _P)


def _add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def ed25519_public_key(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    x, y, z, _ = _mul(a, _G)
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _sshstr(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def openssh_ed25519_private_key(seed: bytes, comment: str = "") -> str:
    seed = seed[:32]
    pub = ed25519_public_key(seed)
    pub_blob = _sshstr(b"ssh-ed25519") + _sshstr(pub)
    check = struct.pack(">I", int.from_bytes(hashlib.sha256(seed).digest()[:4], "big"))
    priv = check + check + pub_blob + _sshstr(seed + pub) + _sshstr(comment.encode())
    priv += bytes(range(1, (8 - len(priv) % 8) % 8 + 1))
    blob = (
        b"openssh-key-v1\x00"
        + _sshstr(b"none")
        + _sshstr(b"none")
        + _sshstr(b"")
        + struct.pack(">I", 1)
        + _sshstr(pub_blob)
        + _sshstr(priv)
    )
    body = base64.b64encode(blob).decode()
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(textwrap.wrap(body, 70))
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def load_external_tokens(path: Path) -> list[ExternalAwsToken]:
    """Load Canarytokens AWS keys.

    Accepts a JSON list of ``{"access_key_id", "secret_access_key", "region"}``
    objects, or the plain ``[default]`` credentials-file format that
    canarytokens.org lets you download (multiple files can be concatenated).
    """
    raw = path.read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if stripped.startswith("[{") or stripped.startswith("[\n") or stripped.startswith("[ ") or stripped == "[]":
        return [ExternalAwsToken.model_validate(x) for x in json.loads(raw)]
    tokens: list[ExternalAwsToken] = []
    current: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("[") and current:
            tokens.append(_from_ini(current))
            current = {}
        elif "=" in line:
            k, v = (s.strip() for s in line.split("=", 1))
            current[k] = v
    if current:
        tokens.append(_from_ini(current))
    return tokens


def _from_ini(d: dict[str, str]) -> ExternalAwsToken:
    return ExternalAwsToken(
        access_key_id=d["aws_access_key_id"],
        secret_access_key=d["aws_secret_access_key"],
        region=d.get("region", "us-east-1"),
    )
