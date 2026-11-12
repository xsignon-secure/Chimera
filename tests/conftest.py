from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from chimera.config import Settings
from chimera.engine import Engine
from chimera.store import Store


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def serve(app: Any, port: int) -> Iterator[str]:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    assert server.started, "server failed to start"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "data_dir": tmp_path / "hp",
        "seed": "test-seed",
        "canary_secret": "test-secret",
        "latency_min_ms": 0,
        "latency_max_ms": 1,
        "log_stdout": False,
        "public_base_url": "https://decoy.example.test",
        "profile": "full",
    }
    base.update(overrides)
    return Settings.model_validate(base)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
async def engine(settings: Settings) -> Any:
    eng = Engine(settings, Store(":memory:"))
    await eng.start()
    yield eng
    await eng.stop()
