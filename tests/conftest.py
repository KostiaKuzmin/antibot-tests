import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_SCRIPT = PROJECT_ROOT / "server.py"


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.2)
    raise RuntimeError(f"Сервер не запустился на {host}:{port} за {timeout}s: {last_err}")


def _split_host_port(url: str) -> tuple[str, int]:
    no_scheme = url.split("://", 1)[1]
    host, port = no_scheme.split(":", 1)
    return host, int(port.split("/", 1)[0])


@pytest.fixture(scope="session")
def base_url() -> str:
    # TEST_BASE_URL задаётся в docker-compose, локально берём 127.0.0.1
    return os.environ.get("TEST_BASE_URL", "http://127.0.0.1:8000")


@pytest.fixture(scope="session", autouse=True)
def antibot_server(base_url: str):
    if os.environ.get("TEST_BASE_URL"):
        _wait_for_port(*_split_host_port(base_url))
        yield base_url
        return

    proc = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT)],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_port(*_split_host_port(base_url))
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture()
def http_client(base_url: str):
    with httpx.Client(base_url=base_url, timeout=10.0, trust_env=False) as client:
        yield client
