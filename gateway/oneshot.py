"""OneShotSession: engine for targets that send only one frame per connection.

Some servers (e.g. GNOME Remote Desktop on Wayland) never push a second
frame on an established connection, so a long-lived daemon has nothing to
observe after connect. The workaround (design doc §2.7) is the one-shot
engine: every operation is its own short-lived `rdputil` process —

    screenshot = connect -> first frame -> save -> disconnect
    action     = connect -> blind-inject -> disconnect

and verification of an action comes from the *next* operation's frame
(blind-send discipline, same loop as the mines pipeline). The class exposes
exactly the RdpSession surface (`call(op, p, timeout)`), so the ToolBox and
both protocol fronts work unchanged; profiles select it with
`"engine": "oneshot"`.

Discipline carried over from field experience:
  * before every connection, orphaned rdputil processes holding an
    ESTABLISHED socket to the target are counted and killed;
  * failed connections retry N times with a pause (profile-tunable) and
    escalate to `server_hung` status instead of silent infinite retry;
  * the target's fixed virtual display (`desktop_size`, e.g. 1024x768 on a
    1280x1024 canvas) is cropped off before stats/scaling so dead edges do
    not dilute observations or skew coordinate mapping.

Passwords are passed on the one-shot CLI (`-p`), never through the
environment: the subcommand does not read RDPUTIL_PASS. Keep argv out of
logs; evidence records never include it.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

from PIL import Image

from .session import DEFAULT_TIMEOUT_S, GatewayError

# Per-attempt subprocess budget: connection ladder + first frame + idle wait.
ATTEMPT_TIMEOUT_S = 120.0

# Set-1 scancodes for the combo grammar (subset the tool surface needs).
# (scancode, extended) — extended keys arrive with the 0xE0 prefix.
_KEY_NAMES: dict[str, tuple[int, bool]] = {
    "ctrl": (0x1D, False), "control": (0x1D, False),
    "shift": (0x2A, False),
    "alt": (0x38, False), "altgr": (0x38, True), "ralt": (0x38, True),
    "win": (0x5B, True), "meta": (0x5B, True), "super": (0x5B, True),
    "esc": (0x01, False), "escape": (0x01, False),
    "enter": (0x1C, False), "return": (0x1C, False),
    "tab": (0x0F, False), "space": (0x39, False),
    "backspace": (0x0E, False), "capslock": (0x3A, False),
    "delete": (0xD3, True), "del": (0xD3, True),
    "insert": (0xD2, True), "ins": (0xD2, True),
    "home": (0xC7, True), "end": (0xCF, True),
    "pgup": (0xC9, True), "pgdn": (0xD1, True), "pagedown": (0xD1, True),
    "up": (0xC8, True), "down": (0xD0, True), "left": (0xCB, True), "right": (0xCD, True),
    "f1": (0x3B, False), "f2": (0x3C, False), "f3": (0x3D, False), "f4": (0x3E, False),
    "f5": (0x3F, False), "f6": (0x40, False), "f7": (0x41, False), "f8": (0x42, False),
    "f9": (0x43, False), "f10": (0x44, False), "f11": (0x57, False), "f12": (0x58, False),
}
# a..z -> set-1 make codes in alphabetical order (0x1e..0x2c).
_LETTERS = "abcdefghijklmnopqrstuvwxyz"
for _i, _ch in enumerate(_LETTERS):
    _KEY_NAMES[_ch] = (0x1E + _i, False)
# digits 1..9,0 top row.
for _i, _ch in enumerate("123456789"):
    _KEY_NAMES[_ch] = (0x02 + _i, False)
_KEY_NAMES["0"] = (0x0B, False)

_MODIFIER_NAMES = {"ctrl", "control", "shift", "alt", "altgr", "ralt", "win", "meta", "super"}


def combo_to_seq(combo: str) -> str:
    """Translate `ctrl+shift+esc` / `super` into a --seq token list.

    Modifier holds use d/ue, the final key taps k/ke, modifiers release in
    reverse order. A `seq:` prefix passes raw tokens through untouched.
    """
    if combo.startswith("seq:"):
        return combo[4:]
    parts = [p.strip().lower() for p in combo.split("+") if p.strip()]
    if not parts:
        raise GatewayError("E_ARGS", "empty key combo")
    tokens: list[str] = []
    mods: list[tuple[int, bool]] = []
    for part in parts:
        key = _KEY_NAMES.get(part)
        if key is None:
            raise GatewayError("E_ARGS", f"unknown key name '{part}' in combo")
        sc, ext = key
        if part in _MODIFIER_NAMES:
            mods.append(key)
            tokens.append(("de0x%02x" if ext else "d0x%02x") % sc)
        else:
            tokens.append(("ke0x%02x" if ext else "k0x%02x") % sc)
    for sc, ext in reversed(mods):
        tokens.append(("ue0x%02x" if ext else "u0x%02x") % sc)
    return ",".join(tokens)


class OneShotSession:
    """RdpSession-compatible facade over per-op one-shot rdputil runs."""

    def __init__(
        self,
        name: str,
        host: str,
        username: str,
        password: str,
        *,
        daemon_path: str | os.PathLike[str] | None = None,
        run_dir: str | Path | None = None,
        golden_rule: bool = True,
        desktop_size: tuple[int, int] | list[int] | None = None,
        retry_attempts: int = 3,
        retry_interval_s: float = 15.0,
        extra_args: list[str] | None = None,
    ):
        self.name = name
        self.host = host
        self.username = username
        self.password = password
        self.daemon_path = Path(daemon_path) if daemon_path else _default_daemon()
        self.run_dir = Path(run_dir) if run_dir else Path("runs") / f"{time.strftime('%Y%m%d_%H%M%S')}_{name}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir = self.run_dir / "artifacts"
        self.artifacts_dir.mkdir(exist_ok=True)
        self.golden_rule = golden_rule
        self.extra_args = extra_args or []

        self.desktop_size = tuple(desktop_size) if desktop_size else None
        self.retry_attempts = max(1, int(retry_attempts))
        self.retry_interval_s = float(retry_interval_s)

        self.desktop: dict | None = None
        self.status = "idle"
        self.last_sig: str | None = None
        self.orphans_reaped = 0
        self._shot_count = 0
        self._golden_done = not golden_rule
        self._evidence_lock = threading.Lock()

    # ------------------------------------------------------------------ life

    def start(self) -> None:
        self.evidence("session_start", {"host": self.host, "user": self.username, "engine": "oneshot"})

    @property
    def dead(self) -> bool:
        return self.status == "closed"

    def close(self) -> None:
        self.status = "closed"
        self.evidence("session_close", {"orphans_reaped": self.orphans_reaped})

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def wait_connected(self, timeout: float = 0.0) -> None:
        """No persistent connection to await; every op is its own session."""

    # ------------------------------------------------------------------- call

    def logged_call(self, op: str, p: dict | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
        return self.call(op, p, timeout)

    def call(self, op: str, p: dict | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
        p = p or {}
        t0 = time.time()
        try:
            r = self._dispatch(op, p, timeout)
        except GatewayError:
            self.evidence(f"op_{op}", {"p": _redact(p), "ok": False})
            raise
        r.setdefault("ok", True)
        self.evidence(f"op_{op}", {"p": _redact(p), "ok": True, "gateway_ms": int((time.time() - t0) * 1000)})
        return r

    def _dispatch(self, op: str, p: dict, timeout: float) -> dict:
        if op == "screenshot":
            return self._op_screenshot(p)
        if op == "click":
            return self._op_click(p)
        if op == "move":
            return self._op_mouse(p, action="move")
        if op == "key":
            return self._op_key(p)
        if op == "type":
            return self._op_type(p)
        if op == "wait":
            time.sleep(min(float(p.get("ms", 1000)) / 1000.0, 60.0))
            return {"ok": True}
        if op == "state":
            return self._op_state()
        unsupported = {
            "scroll": "no wheel events in the one-shot CLI",
            "clipboard_get": "no cliprdr channel in one-shot mode",
            "clipboard_set": "no cliprdr channel in one-shot mode",
            "file_push": "no rdpdr channel in one-shot mode",
            "file_pull": "no rdpdr channel in one-shot mode",
            "resize": "no display-control channel in one-shot mode",
            "refresh": "nothing to refresh; each op reconnects anyway",
        }
        if op in unsupported:
            raise GatewayError("E_UNSUPPORTED", f"one-shot engine: {unsupported[op]}")
        raise GatewayError("E_ARGS", f"unknown op '{op}'")

    # ------------------------------------------------------------------- ops

    def _op_screenshot(self, p: dict) -> dict:
        self._shot_count += 1
        out = self.artifacts_dir / f"shot_{self._shot_count:04d}.png"
        idle = max(2, min(int(p.get("wait_stable_ms", 1500)) // 1000, 15))
        self._connect(["screenshot", "-o", str(out), "--idle-secs", str(idle)])
        stats = self._finalize_frame(out)
        self.desktop = {"w": stats["w"], "h": stats["h"]}
        self.last_sig = f"lum={stats['mean_lum']:.2f} distinct={stats['distinct']}"
        return {"png": str(out), "stable": True, **stats}

    def _op_click(self, p: dict) -> dict:
        self._golden()
        action = "dblclick" if p.get("double") else "click"
        return self._op_mouse(p, action=action)

    def _op_mouse(self, p: dict, action: str) -> dict:
        self._golden()
        args = ["mouse", "--x", str(int(p["x"])), "--y", str(int(p["y"])), "--action", action]
        button = p.get("button", "left")
        if button in ("left", "right", "middle"):
            args += ["--button", button]
        self._connect(args)
        return {"x": p.get("x"), "y": p.get("y"), "action": action}

    def _op_key(self, p: dict) -> dict:
        self._golden()
        seq = combo_to_seq(p["combo"]) if p.get("combo") else p.get("seq")
        if not seq:
            raise GatewayError("E_ARGS", "key needs 'combo' or 'seq'")
        self._connect(["key", "--seq", seq])
        return {"combo": p.get("combo") or p.get("seq")}

    def _op_type(self, p: dict) -> dict:
        self._golden()
        if p.get("mode", "text") == "clipboard":
            raise GatewayError("E_UNSUPPORTED", "one-shot engine: no clipboard paste path; use mode='text'")
        text = str(p.get("text", ""))
        if not text:
            raise GatewayError("E_ARGS", "type needs 'text'")
        self._connect(["key", "--text", text])
        return {"chars": len(text)}

    def _op_state(self) -> dict:
        return {
            "engine": "oneshot",
            "status": self.status,
            "host": self.host,
            "desktop_size": list(self.desktop_size) if self.desktop_size else None,
            "last_png": str(self.artifacts_dir / f"shot_{self._shot_count:04d}.png") if self._shot_count else None,
            "last_sig": self.last_sig,
            "shots": self._shot_count,
            "orphans_reaped": self.orphans_reaped,
            "retry_attempts": self.retry_attempts,
        }

    # -------------------------------------------------------------- mechanics

    def _golden(self) -> None:
        """Golden rule: capture a baseline frame before the session's first input."""
        if self._golden_done:
            return
        self._golden_done = True
        try:
            self._op_screenshot({})
            self.evidence("golden_rule", {"detail": "baseline frame captured before first input"})
        except GatewayError as e:
            self.evidence("golden_rule", {"detail": f"baseline capture failed: {e.code}"})

    def _connect(self, sub_args: list[str], timeout: float = ATTEMPT_TIMEOUT_S) -> subprocess.CompletedProcess:
        """Run one rdputil one-shot subcommand with orphan-reap + retry discipline."""
        base = [str(self.daemon_path), *sub_args, *self.extra_args,
                "--host", self.host, "-u", self.username, "-p", self.password]
        env = {**os.environ,
               "RDPUTIL_CREDSSP": "1",
               "RDPUTIL_T120": "0",
               "RDPUTIL_READ_TIMEOUT_SECS": "20"}
        last_err = ""
        for attempt in range(1, self.retry_attempts + 1):
            self._reap_orphans()
            try:
                proc = subprocess.run(base, env=env, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=timeout)
            except subprocess.TimeoutExpired:
                last_err = f"attempt {attempt}: timed out after {timeout}s"
                self.evidence("connect_fail", {"detail": last_err})
                continue
            if proc.returncode == 0:
                self.status = "idle"
                return proc
            last_err = f"attempt {attempt}: rc={proc.returncode}: {(proc.stderr or '').strip().splitlines()[-1:] }"
            self.evidence("connect_fail", {"detail": last_err})
            if attempt < self.retry_attempts:
                time.sleep(self.retry_interval_s)
        self.status = "server_hung"
        raise GatewayError("E_SERVER_HUNG",
                           f"target did not answer after {self.retry_attempts} attempts; last: {last_err}")

    def _reap_orphans(self) -> None:
        """Kill rdputil processes holding an ESTABLISHED connection to the target."""
        pids = _rdputil_pids()
        if not pids:
            return
        victims: set[int] = set()
        try:
            netstat = _run_windows(["netstat", "-ano"])
            for line in netstat.splitlines():
                fields = line.split()
                if len(fields) >= 5 and fields[2].startswith(f"{self.host}:") and fields[3] == "ESTABLISHED":
                    try:
                        pid = int(fields[4])
                    except ValueError:
                        continue
                    if pid in pids:
                        victims.add(pid)
        except (OSError, subprocess.SubprocessError):
            return
        for pid in victims:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=30)
        if victims:
            self.orphans_reaped += len(victims)
            self.evidence("orphan_reap", {"pids": sorted(victims)})

    def _finalize_frame(self, png: Path) -> dict:
        """Crop the fixed virtual display (dead edges), compute frame stats."""
        img = Image.open(png)
        if self.desktop_size and img.size != tuple(self.desktop_size):
            img = img.crop((0, 0, self.desktop_size[0], self.desktop_size[1]))
            img.save(png)
        img = img.convert("RGB")
        w, h = img.size
        gray = img.convert("L")
        hist = gray.histogram()
        mean_lum = sum(i * n for i, n in enumerate(hist)) / float(w * h)
        colors = img.getcolors(maxcolors=1 << 20)
        distinct = len(colors) if colors is not None else -1
        return {"w": w, "h": h, "mean_lum": round(mean_lum, 2), "distinct": distinct}

    # --------------------------------------------------------------- evidence

    def evidence(self, kind: str, payload: dict) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "vm": self.name, "kind": kind, **payload}
        with self._evidence_lock:
            with open(self.run_dir / "evidence.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _default_daemon() -> Path:
    override = os.environ.get("GATEWAY_RDPUTIL")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "tools" / "rdputil" / "target" / "release" / "rdputil.exe"


def _redact(p: dict) -> dict:
    out = dict(p)
    if "text" in out and len(str(out["text"])) > 40:
        out["text"] = f"<{len(str(out['text']))} chars>"
    return out


def _run_windows(cmd: list[str], timeout: float = 30.0) -> str:
    """Run a native Windows tool and decode its output (OEM codepage, not UTF-8)."""
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    try:
        return proc.stdout.decode("mbcs", errors="replace")
    except (LookupError, ValueError):
        return proc.stdout.decode("utf-8", errors="replace")


def _rdputil_pids() -> set[int]:
    """PIDs of running rdputil.exe images (empty if the tool is unavailable)."""
    try:
        out = _run_windows(["tasklist", "/FI", "IMAGENAME eq rdputil.exe", "/FO", "CSV", "/NH"])
    except (OSError, subprocess.SubprocessError):
        return set()
    pids: set[int] = set()
    for row in out.splitlines():
        fields = [f.strip('"') for f in row.split('","')]
        if len(fields) >= 2 and fields[1].isdigit():
            pids.add(int(fields[1]))
    return pids
