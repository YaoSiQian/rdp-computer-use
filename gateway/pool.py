"""Multi-target registry: name -> connection profile -> one live session.

Profiles come from `gateway/profiles.json` (not committed; contains
environment-specific hosts and usernames — passwords always resolve from the
environment). Schema:

    {
      "win10": {"host": "<host>", "username": "<user>",
                "password_env": "GATEWAY_WIN10_PASS", "rdpdr": true},
      ...
    }

`rdpdr` (optional, default false) starts the daemon with drive redirection
and enables the file_push/file_pull tools; servers that reject the redirect
surface that as an E_UNAVAILABLE error at call time.

`display_control` (optional, default false) attaches the Display Control
dynamic channel (RDPUTIL_DISP=1) so the resize tool can change the remote
resolution; without it the daemon answers E_UNSUPPORTED because the channel
can only be negotiated at connect time.

`engine` (optional, default "daemon") picks the session engine: "daemon" is
the long-lived `rdputil serve` process; "oneshot" runs one short connection
per op for servers that only send a single frame per connection (see
gateway/oneshot.py). One-shot profiles may also set `desktop_size`
([w, h] — fixed virtual display dead-edge crop), `retry_attempts` and
`retry_interval_s`.

When `engine` is not hand-set, `detected_profile.engine_hint` (written by
`probe()`) decides: first_frame_only targets run one-shot, everything else
stays on the daemon. The probe's winning `connect_env` is replayed on
daemon spawns. Hand-set fields always win over detection.

`profiles.sample.json` in this directory shows the schema with placeholder
values. A single RDP session per target is enforced: asking for the same name
twice hands back the same live session.

Sessions come in two modes. The default is a desktop session. `start_app()`
replaces it with an app-scoped RemoteApp (RAIL) session whose lifetime is the
app's lifetime; once the app exits the dead session is discarded and the next
toolbox() call quietly returns to a fresh desktop session.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from .api import ToolBox
from .oneshot import OneShotSession
from .probe import run_probe
from .rdp_file import rdp_to_profile
from .session import GatewayError, RdpSession

logger = logging.getLogger(__name__)

PROFILE_FILE = Path(__file__).resolve().parent / "profiles.json"


def _profiles_path() -> Path:
    override = os.environ.get("GATEWAY_PROFILES")
    return Path(override) if override else PROFILE_FILE


def load_profiles() -> dict:
    path = _profiles_path()
    if not path.exists():
        raise RuntimeError(
            f"profiles file missing: {path} — create it from the sample schema "
            "(hosts and usernames are environment-specific and stay out of the repo)"
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    profiles = raw.get("profiles", raw)
    for name, prof in profiles.items():
        if prof.get("rdp_file"):
            prof = _import_rdp_file(path.parent, name, prof)
            profiles[name] = prof
        env_key = prof.get("password_env", f"GATEWAY_{name.upper()}_PASS")
        prof.setdefault("password_env", env_key)
    return profiles


def _import_rdp_file(base_dir: Path, name: str, prof: dict) -> dict:
    """Resolve an entry's `rdp_file` into gateway-native profile keys.

    The .rdp file supplies the connection facts; keys written in the profile
    entry are the orchestration overlay and win on conflict. Mapping results
    (disabled clipboard, accepted no-ops, ...) are recorded in `rdp_notes`.
    """
    rdp_path = Path(prof["rdp_file"])
    if not rdp_path.is_absolute():
        rdp_path = base_dir / rdp_path
    if not rdp_path.exists():
        raise RuntimeError(f"profile '{name}': rdp_file not found: {rdp_path}")
    imported = rdp_to_profile(rdp_path)
    merged = {**imported, **{k: v for k, v in prof.items() if k != "rdp_file"}}
    merged["rdp_file"] = str(rdp_path)
    for note in imported["rdp_notes"]:
        logger.info("profile '%s' rdp_file: %s", name, note)
    return merged


def save_profiles(profiles: dict) -> None:
    path = _profiles_path()
    path.write_text(json.dumps({"profiles": profiles}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


class SessionPool:
    """Owns live sessions; one per profile name; thread-safe."""

    def __init__(self, daemon_path: str | None = None, run_root: str | Path | None = None):
        self.profiles = load_profiles()
        self.daemon_path = daemon_path
        self.run_root = Path(run_root) if run_root else Path("runs")
        self._lock = threading.Lock()
        self._sessions: dict[str, RdpSession | OneShotSession] = {}
        self._boxes: dict[str, ToolBox] = {}

    def toolbox(self, name: str, golden_rule: bool = True) -> ToolBox:
        """Get (or create) the live session for a profile and bind tools.

        A session that has died (app exit in RemoteApp mode, daemon crash) is
        discarded here: the next call lands on a fresh desktop session."""
        with self._lock:
            box = self._boxes.get(name)
            if box is not None:
                session = self._sessions.get(name)
                if session is not None and not session.dead:
                    return box
                self._boxes.pop(name, None)
                self._sessions.pop(name, None)
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass
            prof = self.profiles.get(name)
            if prof is None:
                raise KeyError(f"unknown profile '{name}' (have: {', '.join(sorted(self.profiles))})")
            session = self._new_session(name, prof, golden_rule, remote_app=None)
            session.start()
            session.wait_connected()
            box = ToolBox(session)
            self._sessions[name] = session
            self._boxes[name] = box
            return box

    def start_app(self, name: str, app: str, args: str | None = None, workdir: str | None = None) -> dict:
        """Swap the live session for `name` over to a RemoteApp (RAIL) session
        that launches `app`, and return the daemon's launch verdict.

        The previous session (desktop or app) is disconnected first — targets
        host a single interactive session. The RemoteApp session ends when the
        app exits; subsequent toolbox() calls then rebuild a desktop session."""
        with self._lock:
            prof = self.profiles.get(name)
            if prof is None:
                raise KeyError(f"unknown profile '{name}' (have: {', '.join(sorted(self.profiles))})")
            detected = prof.get("detected_profile") or {}
            if (detected.get("capabilities") or {}).get("remote_app") is False:
                raise GatewayError(
                    "E_UNSUPPORTED",
                    "probe judged this target RemoteApp-incapable (detected_profile.capabilities.remote_app=false); "
                    "use the desktop session",
                )
            old = self._sessions.pop(name, None)
            self._boxes.pop(name, None)
            # The new connection kicks the old one server-side anyway;
            # closing first keeps the goodbye on our terms.
            if old is not None:
                try:
                    old.close()
                except Exception:
                    pass
            session = None
            try:
                session = self._new_session(name, prof, True, remote_app={"app": app, "args": args, "workdir": workdir})
                session.start()
                session.wait_connected()
                rail = "none"
                deadline = time.time() + 30.0
                while time.time() < deadline:
                    rail = session.call("state", {}).get("rail_exec", "none")
                    if rail in ("ok", "failed"):
                        break
                    time.sleep(1.0)
                if rail != "ok":
                    raise GatewayError(
                        "E_APP_START",
                        f"server did not launch '{app}' (rail_exec={rail}); the guest must allow unlisted RemoteApp programs",
                    )
                box = ToolBox(session)
                self._sessions[name] = session
                self._boxes[name] = box
                return {"ok": True, "app": app, "rail_exec": rail}
            except Exception:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass
                raise

    def _new_session(self, name: str, prof: dict, golden_rule: bool, *, remote_app: dict | None):
        password = os.environ.get(prof["password_env"], "")
        if not password:
            raise RuntimeError(f"environment variable {prof['password_env']} not set")
        detected = prof.get("detected_profile") or {}
        # Replay exactly the env combination the probe's connect ladder found
        # working (e.g. CredSSP with T120 announce suppressed), not just a
        # label of it.
        extra_env: dict[str, str] = dict(detected.get("connect_env") or {})
        if prof.get("display_control"):
            extra_env["RDPUTIL_DISP"] = "1"
        common = {
            "name": name,
            "host": prof["host"],
            "username": prof["username"],
            "password": password,
            "daemon_path": self.daemon_path or prof.get("daemon"),
            "run_dir": self.run_root / f"{prof.get('run_prefix', '')}{name}",
            "golden_rule": golden_rule,
        }
        if self._engine(prof) == "oneshot":
            if remote_app:
                raise GatewayError("E_UNSUPPORTED", "one-shot engine has no RemoteApp session mode")
            if prof.get("port") not in (None, 3389) or prof.get("domain"):
                raise GatewayError(
                    "E_UNSUPPORTED",
                    "one-shot connections accept no port/domain; values imported from an rdp_file need the "
                    "daemon engine (set engine: daemon or clear the keys)",
                )
            return OneShotSession(
                desktop_size=prof.get("desktop_size"),
                retry_attempts=int(prof.get("retry_attempts", 3)),
                retry_interval_s=float(prof.get("retry_interval_s", 15.0)),
                **common,
            )
        extra_args: list[str] = []
        if prof.get("port") not in (None, 3389):
            extra_args += ["--port", str(prof["port"])]
        if prof.get("domain"):
            extra_args += ["--domain", prof["domain"]]
        if prof.get("desktop_size"):
            width, height = prof["desktop_size"]
            extra_args += ["--w", str(width), "--h", str(height)]
        return RdpSession(
            rdpdr=bool(prof.get("rdpdr", False)),
            cliprdr=bool(prof.get("cliprdr", True)),
            remote_app=remote_app,
            extra_env=extra_env,
            extra_args=extra_args,
            **common,
        )

    @staticmethod
    def _engine(prof: dict) -> str:
        """Hand-set engine wins (prior seeds keep precedence over detection)."""
        engine = prof.get("engine")
        if engine:
            return engine
        detected = prof.get("detected_profile") or {}
        return "oneshot" if detected.get("engine_hint") == "oneshot" else "daemon"

    def probe(self, name: str) -> dict:
        """Run the detection pipeline against a target and merge the
        result into its profile entry as `detected_profile` (file rewritten).
        Ladder outcomes are reported, not raised; only configuration problems
        (unknown name, missing password env) raise."""
        profiles = load_profiles()
        prof = profiles.get(name)
        if prof is None:
            raise KeyError(f"unknown profile '{name}' (have: {', '.join(sorted(profiles))})")
        # The probe takes over the interactive session; the pooled connection
        # would race every probe stage's arbitration (the RAIL handshake is
        # the sensitive one). toolbox() rebuilds it on the next call.
        self.close(name)
        try:
            result = run_probe(name, prof, daemon_path=self.daemon_path, run_root=self.run_root)
        finally:
            save_profiles(profiles)
            self.profiles = load_profiles()
        return result

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
            n: {
                "status": s.status,
                "last_sig": s.last_sig,
                "desktop": s.desktop,
                "run_dir": str(s.run_dir),
                "remote_app": (s.remote_app or {}).get("app") if getattr(s, "remote_app", None) else None,
            }
            for n, s in self._sessions.items()
        }
