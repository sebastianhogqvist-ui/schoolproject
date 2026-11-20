#!/usr/bin/env python3
"""Multi-service launcher for NULLFORGE.

Starts the gateway plus every backend service (license, session, security,
integrity, admin) as subprocesses, waits for all of them to register in the
service registry, then waits for all processes to complete.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_DIR = SCRIPT_DIR.parent
ENV_FILE = SERVER_DIR / ".env"
REGISTRY_PATH = SERVER_DIR / "runtime" / "services.json"

DEFAULT_TIMEOUT = 30.0
POLL_INTERVAL = 0.5

SERVICES: list[tuple[str, dict[str, str]]] = [
    ("gateway",   {"SERVICE_MODE": "gateway",   "SERVER_HOST": "127.0.0.1", "SERVER_PORT": "8080"}),
    ("license",   {"SERVICE_MODE": "license",   "SERVER_HOST": "127.0.0.1"}),
    ("session",   {"SERVICE_MODE": "session",   "SERVER_HOST": "127.0.0.1"}),
    ("security",  {"SERVICE_MODE": "security",  "SERVER_HOST": "127.0.0.1"}),
    ("integrity", {"SERVICE_MODE": "integrity", "SERVER_HOST": "127.0.0.1"}),
    ("admin",     {"SERVICE_MODE": "admin",     "SERVER_HOST": "127.0.0.1"}),
]


def load_env() -> None:
    """Load environment variables from server/.env if present."""
    if ENV_FILE.exists():
        count = 0
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)
            count += 1
        print(f"[start_services] loaded {count} variables from {ENV_FILE}")
    else:
        print(f"[start_services] no .env file at {ENV_FILE}; using existing environment")


def build_env(overrides: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env.update(overrides)
    return env


def start_process(name: str, overrides: dict[str, str]) -> subprocess.Popen:
    env = build_env(overrides)
    cmd = [sys.executable, "-m", "uvicorn", "app.main:app"]
    proc = subprocess.Popen(
        cmd,
        cwd=str(SERVER_DIR),
        env=env,
        stdout=None,
        stderr=None,
    )
    print(f"[start_services] started {name} (pid {proc.pid})")
    return proc


def read_registry() -> dict:
    try:
        with REGISTRY_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def wait_for_services(timeout: float = DEFAULT_TIMEOUT) -> bool:
    expected = {name for name, _ in SERVICES}
    deadline = time.time() + timeout
    while time.time() < deadline:
        registered = set(read_registry().keys())
        missing = sorted(expected - registered)
        if not missing:
            return True
        print(f"[start_services] waiting for services: {', '.join(missing)}")
        time.sleep(POLL_INTERVAL)
    registered = set(read_registry().keys())
    still_missing = sorted(expected - registered)
    print(f"[start_services] startup timeout: services still missing: {', '.join(still_missing)}")
    return False


def print_table(processes: list[subprocess.Popen], names: list[str]) -> None:
    print("\n=== NULLFORGE services running ===")
    print(f"{'Service':<12} {'PID':<8} {'Status'}")
    print("-" * 30)
    for name, proc in zip(names, processes):
        status = "running" if proc.poll() is None else f"exited ({proc.returncode})"
        print(f"{name:<12} {proc.pid:<8} {status}")
    print("================================\n")


def main() -> int:
    load_env()

    processes: list[subprocess.Popen] = []
    names: list[str] = []

    def shutdown(signum=None, frame=None) -> None:
        print("\n[start_services] shutting down all services...")
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        sys.exit(0 if signum is not None else 1)

    signal.signal(signal.SIGINT, shutdown)

    try:
        for name, overrides in SERVICES:
            proc = start_process(name, overrides)
            processes.append(proc)
            names.append(name)

        ok = wait_for_services()
        print_table(processes, names)

        if not ok:
            print("[start_services] not all services registered within timeout")
            shutdown()
            return 1

        while True:
            if all(proc.poll() is not None for proc in processes):
                break
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
