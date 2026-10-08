"""Multi-target registry: name -> connection profile -> one live session.

Profiles come from `gateway/profiles.json` (not committed; contains
environment-specific hosts and usernames — passwords always resolve from the
environment). Schema:

    {
      "win10": {"host": "<host>", "username": "<user>",
                "password_env": "GATEWAY_WIN10_PASS"},
      ...
    }

`profiles.sample.json` in this directory shows the schema with placeholder
values. A single RDP session per target is enforced: asking for the same name
twice hands back the same live session.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .api import ToolBox
from .session import RdpSession

PROFILE_FILE = Path(__file__).resolve().parent / "profiles.json"


def load_profiles() -> dict:
    if not PROFILE_FILE.exists():
        raise RuntimeError(
            f"profiles file missing: {PROFILE_FILE} — create it from the sample schema "
            "(hosts and usernames are environment-specific and stay out of the repo)"
        )
    raw = json.loads(PROFILE_FILE.read_text(encoding="utf-8"))
    profiles = raw.get("profiles", raw)
    for name, prof in profiles.items():
        env_key = prof.get("password_env", f"GATEWAY_{name.upper()}_PASS")
        prof.setdefault("password_env", env_key)
    return profiles


class SessionPool:
    """Owns live sessions; one per profile name; thread-safe."""

    def __init__(self, daemon_path: str | None = None, run_root: str | Path | None = None):
        self.profiles = load_profiles()
        self.daemon_path = daemon_path
        self.run_root = Path(run_root) if run_root else Path("runs")
        self._lock = threading.Lock()
        self._sessions: dict[str, RdpSession] = {}
        self._boxes: dict[str, ToolBox] = {}

    def toolbox(self, name: str, golden_rule: bool = True) -> ToolBox:
        """Get (or create) the live session for a profile and bind tools."""
        with self._lock:
            box = self._boxes.get(name)
            if box is not None:
                return box
            prof = self.profiles.get(name)
            if prof is None:
                raise KeyError(f"unknown profile '{name}' (have: {', '.join(sorted(self.profiles))})")
            password = os.environ.get(prof["password_env"], "")
            if not password:
                raise RuntimeError(f"environment variable {prof['password_env']} not set")
            session = RdpSession(
                name,
                prof["host"],
                prof["username"],
                password,
                daemon_path=self.daemon_path or prof.get("daemon"),
                run_dir=self.run_root / f"{prof.get('run_prefix', '')}{name}",
                golden_rule=golden_rule,
            )
            session.start()
            session.wait_connected()
            box = ToolBox(session)
            self._sessions[name] = session
            self._boxes[name] = box
            return box

    def close(self, name: str | None = None) -> None:
        with self._lock:
            names = [name] if name else list(self._sessions)
            for n in names:
                session = self._sessions.pop(n, None)
                self._boxes.pop(n, None)
                if session:
                    session.close()

    def close_all(self) -> None:
        self.close()

    def status(self) -> dict:
        return {
            n: {"status": s.status, "last_sig": s.last_sig, "desktop": s.desktop, "run_dir": str(s.run_dir)}
            for n, s in self._sessions.items()
        }
