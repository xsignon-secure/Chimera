from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from chimera.canary import CanaryWatermarker, load_external_tokens
from chimera.fakeworld import FakeWorld
from chimera.store import Store


def wm(tmp_path: Path | None = None, external: Path | None = None) -> CanaryWatermarker:
    return CanaryWatermarker(Store(":memory:"), "k", "https://decoy.example.test", external)


async def test_formats_look_real() -> None:
    w = wm()
    aws = await w.issue("aws_key", session_id="s", source_ip="1.2.3.4", tool="t")
    assert re.fullmatch(r"AKIA[A-Z2-7]{16}", aws.value)
    assert aws.secondary and len(aws.secondary) == 40
    vault = await w.issue("vault_token", session_id="s", source_ip="1.2.3.4", tool="t")
    assert vault.value.startswith("hvs.") and len(vault.value) == 94
    assert not vault.value.endswith("aaaa"), "no padding tells"
    ssh = await w.issue("ssh_key", session_id="s", source_ip="1.2.3.4", tool="t")
    assert ssh.value.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    jwt = await w.issue("jwt", session_id="s", source_ip="1.2.3.4", tool="t", context="svc")
    assert jwt.value.count(".") == 2
    db = await w.issue(
        "db_url", session_id="s", source_ip="1.2.3.4", tool="t", context="postgresql://u:{password}@h:5432/db"
    )
    assert db.value.startswith("postgresql://u:") and "{password}" not in db.value
    url = await w.issue("callback_url", session_id="s", source_ip="1.2.3.4", tool="t", context="sso/x")
    assert url.value.startswith("https://decoy.example.test/sso/x/")


async def test_every_issue_is_unique_and_detectable() -> None:
    w = wm()
    values = set()
    for i in range(50):
        c = await w.issue("password", session_id=f"s{i % 3}", source_ip="10.0.0.1", tool="t")
        values.add(c.value)
        assert w.scan(f"login with {c.value} please") == [c.canary_id]
    assert len(values) == 50
    assert w.scan("nothing to see") == []


async def test_reuse_survives_restart() -> None:
    store = Store(":memory:")
    w1 = CanaryWatermarker(store, "k", "https://d.test")
    c = await w1.issue("api_key", session_id="s", source_ip="ip", tool="t")
    w2 = CanaryWatermarker(store, "k", "https://d.test")
    await w2.warm()
    assert w2.scan(c.value) == [c.canary_id]


async def test_external_canarytokens_are_served_first(tmp_path: Path) -> None:
    f = tmp_path / "tokens.ini"
    f.write_text(
        "[default]\naws_access_key_id = AKIAEXTERNAL00000001\naws_secret_access_key = abc\n"
        "[default]\naws_access_key_id = AKIAEXTERNAL00000002\naws_secret_access_key = def\n"
        "region = eu-west-1\n"
    )
    toks = load_external_tokens(f)
    assert [t.access_key_id for t in toks] == ["AKIAEXTERNAL00000001", "AKIAEXTERNAL00000002"]
    w = wm(external=f)
    a = await w.issue("aws_key", session_id="a", source_ip="ip", tool="t")
    b = await w.issue("aws_key", session_id="b", source_ip="ip", tool="t")
    assert a.external and b.external and a.value != b.value
    c = await w.issue("aws_key", session_id="c", source_ip="ip", tool="t")
    assert c.value in {"AKIAEXTERNAL00000001", "AKIAEXTERNAL00000002"}  # rotates when exhausted


def test_external_json(tmp_path: Path) -> None:
    f = tmp_path / "t.json"
    f.write_text(json.dumps([{"access_key_id": "AKIAX", "secret_access_key": "s"}]))
    assert load_external_tokens(f)[0].access_key_id == "AKIAX"


def test_fake_world_is_deterministic_and_private() -> None:
    a, b = FakeWorld("seed-1"), FakeWorld("seed-1")
    assert a.company == b.company and [e.username for e in a.employees] == [e.username for e in b.employees]
    assert FakeWorld("seed-2").aws_account_id != a.aws_account_id or FakeWorld("seed-2").company != a.company
    for h in a.hosts:
        assert ipaddress.ip_address(h.ip).is_private, h.ip
    assert a.employee("EMP-unknown") == a.employee("EMP-unknown")
