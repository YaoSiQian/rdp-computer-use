"""Target probe: synthesize a `detected_profile` for an unfamiliar target.

Implements the design's detection pipeline (§2.8 as revised by §2.8.1):
everything is judged from host + account + password — no per-name knowledge.
Steps, each failure carrying its §7.2 ladder code:

1. TCP dial (E_CONN_TARGET on failure);
2. daemon-mode connect, default security first, then an escalation retry
   (CredSSP with the T120 announce suppressed) when the first attempt is
   refused at the negotiation/auth level (E_AUTH) — the winning env
   combination is recorded as `connect_env` for later daemon spawns;
3. both attempts failing marks the target one-shot-engine territory
   (the per-op engine owns retry discipline and works where the long-lived
   daemon cannot) — still a successful classification;
4. frame-mode discrimination on the surviving connection: screenshots are
   compared byte-exactly, and a hover sweep across the taskbar edge must
   repaint (cursor moves alone do not touch the bitmap stream); failing
   that, a Super tap — an input whose effect persists — must repaint too;
   failing that, a reconnect whose first frame reflects the tap marks
   `first_frame_only`; a fully static desktop stays honestly
   `unknown_static`. A session that dies mid-probe (first-connect kick)
   costs one clean retry of the whole frame stage;
5. RemoteApp probe on a fresh connection: `rail_exec` ok/failed both prove
   the RAIL channel; connect/activation refusal proves the opposite;
6. the first_connect_kick instability is recorded only when observed during
   the probe window itself (active session dying on its own).

The result is merged into the profile entry as `detected_profile` and left
for human review; hand-set fields (notably `engine`) keep precedence.
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

from .session import GatewayError, RdpSession

CONNECT_TIMEOUT_S = 90.0
RAIL_VERDICT_TIMEOUT_S = 30.0

# RemoteApp probe payload: present everywhere, exits by itself, needs no
# allowlist beyond unlisted-program permission.
RAIL_PROBE_APP = "cmd.exe"
RAIL_PROBE_ARGS = "/c exit"


def _png_bytes(shot: dict) -> bytes:
    """The shot's PNG as saved by the daemon. Byte-exact: identical pixels
    encode identically, and a taskbar hover highlight is far below the
    resolution of rounded luminance stats."""
    return Path(shot["png"]).read_bytes()


class TargetProbe:
    """One probe episode against one host. `run()` returns the report dict;
    ladder outcomes are reported, never raised."""

    def __init__(self, name: str, host: str, username: str, password: str, *, daemon_path=None, run_root=None):
        self.name = name
        self.host = host
        self.username = username
        self.password = password
        self.daemon_path = daemon_path
        self.run_root = Path(run_root) if run_root else Path("runs")
        self.episodes = 0
        self.auth: str | None = None
        self.connect_env: dict = {}

    # ------------------------------------------------------------- plumbing

    def _session(self, extra_env: dict | None = None, remote_app: dict | None = None) -> RdpSession:
        self.episodes += 1
        run_dir = self.run_root / f"probe_{self.name}_{self.episodes:02d}_{time.strftime('%H%M%S')}"
        return RdpSession(
            name=self.name,
            host=self.host,
            username=self.username,
            password=self.password,
            daemon_path=self.daemon_path,
            run_dir=run_dir,
            golden_rule=False,
            cliprdr=False,
            extra_env=extra_env,
            remote_app=remote_app,
        )

    def _connect(self, session: RdpSession, timeout: float = CONNECT_TIMEOUT_S) -> None:
        session.start()
        session.wait_connected(timeout)

    # ----------------------------------------------------------------- run

    def run(self) -> dict:
        report: dict = {"probed_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "ladder": []}
        try:
            self._tcp_probe(report)
        except GatewayError as e:
            return {"ok": False, "error_code": e.code, "probed_at": report["probed_at"], "ladder": report["ladder"]}

        profile, session = self._classify(report)
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        report["ok"] = True
        report["detected_profile"] = profile
        return report

    # -------------------------------------------------------------- stages

    def _tcp_probe(self, report: dict) -> None:
        t0 = time.time()
        try:
            with socket.create_connection((self.host, 3389), timeout=3.0):
                pass
        except OSError as e:
            raise GatewayError("E_CONN_TARGET", f"TCP dial {self.host}:3389 failed: {e}") from e
        report["ladder"].append({"level": "tcp", "code": "OK", "ms": int((time.time() - t0) * 1000)})

    def _classify(self, report: dict) -> tuple[dict, RdpSession | None]:
        """Connect ladder + frame-mode + RemoteApp probe. Returns the detected
        profile and (for the caller to close) the live session if any."""
        profile: dict = {
            "frame_mode": None,
            "auth": None,
            "connect_env": {},
            "capabilities": {"remote_app": None, "cliprdr": None, "rdpdr": None},
            "instability": {},
        }
        session = None
        for attempt in (1, 2):
            if session is None:
                env, session = self._connect_ladder(report)
                if session is None:
                    # Every daemon-mode connect was refused at protocol level:
                    # exactly the one-shot engine's patient (per-op sessions,
                    # retry discipline).
                    profile["engine_hint"] = "oneshot"
                    report["ladder"].append({"level": "engine", "code": "E_ONESHOT_TERRITORY"})
                    return profile, None
            profile["auth"] = self.auth
            profile["connect_env"] = dict(self.connect_env)
            try:
                profile["frame_mode"], session = self._frame_mode(session, report)
                break
            except GatewayError as e:
                report["ladder"].append({"level": "frame_probe", "code": e.code, "attempt": attempt})
                if session.dead:
                    # First-connect-kick-style death mid-probe: one clean retry.
                    profile["instability"]["first_connect_kick"] = True
                session = None
        fm = profile["frame_mode"]
        if fm == "first_frame_only":
            profile["engine_hint"] = "oneshot"
        elif fm in ("push", "unknown_static"):
            profile["engine_hint"] = "daemon"
        else:
            profile["engine_hint"] = None
        if session is not None and session.dead:
            report["ladder"].append({"level": "instability", "code": "E_SESSION_KICKED", "sig": session.last_sig})
            profile["instability"]["first_connect_kick"] = True
            session = None
        # One connection at a time: the target hosts a single interactive
        # session, and the RAIL handshake races the arbitration that a
        # still-open desktop session triggers.
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        # The RemoteApp probe owns a fresh connection, so it runs even when
        # the main one died mid-probe — a one-shot kick does not predict the
        # next connection's fate.
        try:
            profile["capabilities"]["remote_app"] = self._rail_probe(report)
        except GatewayError as e:
            report["ladder"].append({"level": "rail", "code": e.code})
        return profile, None

    def _connect_ladder(self, report: dict) -> tuple[dict | None, RdpSession | None]:
        """Default security first; an escalation retry on auth-level refusal.
        The retry carries the observed patient combination for servers that
        demand CredSSP and also choke on the T120 announce. Returns the
        winning env dict (or None) plus a live session; (None, None) means
        every attempt was refused at protocol level — one-shot territory."""
        attempts = (
            (None, None),
            ({"RDPUTIL_CREDSSP": "1", "RDPUTIL_T120": "0"}, "credssp"),
        )
        for extra_env, auth in attempts:
            session = self._session(extra_env=extra_env)
            try:
                self._connect(session)
                self.auth = auth
                self.connect_env = dict(extra_env or {})
                return extra_env, session
            except GatewayError as e:
                report["ladder"].append({"level": "connect", "code": e.code, "sig": session.last_sig})
                try:
                    session.close()
                except Exception:
                    pass
                if e.code not in ("E_AUTH", "E_CAPABILITY"):
                    # Transport-level death (kicked, no frame) — a CredSSP
                    # retry would not change this class of failure.
                    return None, None
        return None, None

    def _frame_mode(self, session: RdpSession, report: dict) -> tuple[str | None, RdpSession | None]:
        """Judge how the target pushes frames. Returns (mode, live session to
        keep). Screenshots are compared byte-exactly: a taskbar hover
        highlight moves a few hundred pixels and does not show up in rounded
        luminance stats."""
        try:
            base = session.call("screenshot", {"wait_stable_ms": 3000, "tol_px": 64}, timeout=120)
        except GatewayError as e:
            report["ladder"].append({"level": "first_frame", "code": "E_NOFRAME", "detail": e.detail})
            return None, session
        report["desktop"] = {"w": base["w"], "h": base["h"]}
        w, h = base["w"], base["h"]
        # Hover sweep along the taskbar edge: Start button, pinned-app zone,
        # middle, clock. Hover highlights repaint; the cursor itself is not
        # part of the bitmap stream.
        for fx in (0.006, 0.12, 0.3, 0.5, 0.7, 0.93):
            x = max(8, min(w - 8, round(w * fx)))
            session.call("move", {"x": x, "y": h - 8})
            time.sleep(0.35)
        after = session.call("screenshot", {"wait_stable_ms": 2500, "tol_px": 64}, timeout=120)
        if _png_bytes(base) != _png_bytes(after):
            return "push", session
        # Hover highlights do not necessarily persist across a connection, so
        # next send an input whose effect does: the Super key opens Start /
        # Activities — a real state change that any push server must repaint
        # in-connection, and that a persistent desktop must show in the next
        # connection's first frame.
        try:
            session.call("key", {"combo": "win"})
            time.sleep(1.2)
            opened = session.call("screenshot", {"wait_stable_ms": 2500, "tol_px": 64}, timeout=120)
            if _png_bytes(base) != _png_bytes(opened):
                try:
                    session.call("key", {"combo": "esc"})
                except GatewayError:
                    pass
                return "push", session
        except GatewayError as e:
            report["ladder"].append({"level": "super_tap", "code": e.code})
        # Nothing moved in-connection: a fully static desktop and a one-frame
        # server look identical while connected. Reconnect and read the first
        # frame — it must reflect the Super tap if the server only ever sends
        # one.
        try:
            session.close()
        except Exception:
            pass
        session2 = self._session(extra_env=self.connect_env or None)
        try:
            self._connect(session2)
            first = session2.call("screenshot", {"wait_stable_ms": 1500, "tol_px": 64}, timeout=120)
            mode = "first_frame_only" if _png_bytes(first) != _png_bytes(base) else "unknown_static"
            try:
                session2.call("key", {"combo": "esc"})
            except GatewayError:
                pass
            return mode, session2
        except GatewayError as e:
            report["ladder"].append({"level": "reconnect", "code": e.code})
            try:
                session2.close()
            except Exception:
                pass
            return "unknown_static", None

    def _rail_probe(self, report: dict) -> bool | None:
        session = self._session(
            extra_env=self.connect_env or None,
            remote_app={"app": RAIL_PROBE_APP, "args": RAIL_PROBE_ARGS},
        )
        try:
            try:
                self._connect(session)
            except GatewayError as e:
                report["ladder"].append({"level": "rail", "code": e.code})
                return False
            deadline = time.time() + RAIL_VERDICT_TIMEOUT_S
            verdict = "none"
            while time.time() < deadline:
                verdict = session.call("state", {}).get("rail_exec", "none")
                if verdict in ("ok", "failed") or session.dead:
                    break
                time.sleep(1.0)
            if verdict in ("ok", "failed"):
                return True
            report["ladder"].append({"level": "rail", "code": "E_VERDICT_TIMEOUT", "verdict": verdict})
            return False
        finally:
            try:
                session.close()
            except Exception:
                pass


def resolve_password(prof: dict, name: str) -> str:
    env_key = prof.get("password_env", f"GATEWAY_{name.upper()}_PASS")
    password = os.environ.get(env_key, "")
    if not password:
        raise GatewayError("E_CONFIG", f"environment variable {env_key} not set")
    return password


def run_probe(name: str, prof: dict, *, daemon_path=None, run_root=None) -> dict:
    """Probe one profile entry (host/username/password_env) and attach the
    result as its `detected_profile`. Returns the full probe report."""
    probe = TargetProbe(
        name,
        prof["host"],
        prof["username"],
        resolve_password(prof, name),
        daemon_path=daemon_path,
        run_root=run_root,
    )
    result = probe.run()
    if result.get("detected_profile"):
        prof["detected_profile"] = result["detected_profile"]
    return result
