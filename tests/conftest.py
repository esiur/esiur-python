"""Shared fixtures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
TS_PATH = Path(os.environ.get("ESIUR_TS_PATH", ROOT.parent / "esiur-ts")).resolve()


@pytest.fixture(scope="session")
def ts_server() -> Iterator[dict[str, Any]]:
    """A running esiur-ts ``EpServer``: ``{"port", "greeterId", "otherId"}``. Its resources keep
    their state for the whole session, so tests compare against what they read, not constants."""
    if shutil.which("node") is None or not (TS_PATH / "node_modules" / "esbuild").is_dir():
        pytest.skip("needs Node and an esiur-ts checkout with its dependencies installed")
    process = subprocess.Popen(
        ["node", str(ROOT / "tools" / "ts-test-server.mjs"), str(TS_PATH)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None and process.stdin is not None
    stdout = process.stdout
    lines: list[str] = []
    reader = threading.Thread(target=lambda: lines.append(stdout.readline()), daemon=True)
    reader.start()
    reader.join(60)
    if not lines or not lines[0].strip():
        process.kill()
        stderr = process.stderr.read() if process.stderr else ""
        pytest.fail(f"the esiur-ts test server did not start: {stderr}")
    try:
        yield json.loads(lines[0])
    finally:
        process.stdin.close()  # the server exits when stdin closes
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
        process.stdout.close()
        if process.stderr:
            process.stderr.close()


@pytest.fixture
def ts_client_command() -> Callable[[int], list[str]]:
    """The command that runs the esiur-ts test client (tools/ts-test-client.mjs) against a server
    on ``port``; skips the test when Node or esiur-ts is missing."""
    if shutil.which("node") is None or not (TS_PATH / "node_modules" / "esbuild").is_dir():
        pytest.skip("needs Node and an esiur-ts checkout with its dependencies installed")

    def command(port: int) -> list[str]:
        return ["node", str(ROOT / "tools" / "ts-test-client.mjs"), str(port), str(TS_PATH)]

    return command
