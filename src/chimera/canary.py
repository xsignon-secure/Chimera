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
import secrets
import string
import textwrap
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from chimera.models import CanaryRecord
from chimera.store import Store

CanaryKind = Literal["aws_key", "password", "ssh_key", "vault_token", "db_url", "api_key", "callback_url", "jwt"]

_B62 = string.ascii_letters + string.digits
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


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


class ExternalAwsToken(BaseModel):
    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"


class CanaryWatermarker:
    def __init__(self, store: Store, secret: str, public_base_url: str, external_file: Path | None = None) -> None:
        self._store = store
        self._key = secret.encode()
        self._base = public_base_url.rstrip("/")
        self._markers: dict[str, str] = {}
        self._external: list[ExternalAwsToken] = []
        if external_file:
            self._external = load_external_tokens(external_file)

    async def warm(self) -> None:
        """Load previously issued markers so reuse is detected across restarts."""
        for rec in await self._store.all_canaries():
            self._markers[_marker_for(rec.kind, rec.value)] = rec.canary_id

    # -- derivation --------------------------------------------------------
    def _digest(self, *parts: str) -> bytes:
        return hmac.new(self._key, "|".join(parts).encode(), hashlib.sha256).digest()

    @staticmethod
    def _alphabet(raw: bytes, alphabet: str, n: int) -> str:
        # Expand with SHAKE so long outputs never run out of entropy (no padding tells).
        stream = hashlib.shake_256(raw).digest(n * 2)
        return "".join(alphabet[int.from_bytes(stream[i * 2 : i * 2 + 2], "big") % len(alphabet)] for i in range(n))

    async def issue(
        self, kind: CanaryKind, *, session_id: str, source_ip: str, tool: str, context: str = ""
    ) -> IssuedCanary:
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
            body = base64.b64encode(b"openssh-key-v1\x00" + d + d2 + self._digest("3", nonce) * 9).decode()
            value = (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + "\n".join(textwrap.wrap(body, 70))
                + "\n-----END OPENSSH PRIVATE KEY-----"
            )
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
        self._markers[marker] = canary_id
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
        return IssuedCanary(
            canary_id=canary_id, kind=kind, value=value, secondary=secondary, marker=marker, external=external
        )

    async def _next_external(self) -> ExternalAwsToken | None:
        if not self._external:
            return None
        used = await self._store.external_values_in_use()
        for tok in self._external:
            if tok.access_key_id not in used:
                return tok
        # Pool exhausted: rotate. Attribution then relies on issue timestamps.
        return self._external[secrets.randbelow(len(self._external))]

    # -- detection ---------------------------------------------------------
    def scan(self, text: str) -> list[str]:
        """Return canary ids whose marker appears in ``text``."""
        if not text or not self._markers:
            return []
        return sorted({cid for marker, cid in self._markers.items() if marker in text})

    def callback_token_to_id(self, url_path: str) -> str | None:
        hits = self.scan(self._base + url_path)
        return hits[0] if hits else None


def _marker_for(kind: str, value: str) -> str:
    if kind == "ssh_key":
        lines = value.splitlines()
        return lines[1][:48] if len(lines) > 1 else value[:48]
    if kind == "jwt":
        return value.rsplit(".", 1)[-1]
    if kind == "callback_url":
        return value.rsplit("/", 1)[-1]
    return value


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
