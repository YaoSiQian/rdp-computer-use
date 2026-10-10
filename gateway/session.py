"""RdpSession: owns one `rdputil serve` daemon process.

The daemon speaks line-delimited JSON on stdin/stdout (one response per
request plus asynchronous `ev` events). This class turns that into a Python
request/response API and keeps the evidence trail (JSONL) alongside the
daemon's PNG artifacts.

Threading model: one reader thread consumes stdout and fan-outs responses by
request id; callers block on per-request events. Writes to the daemon's stdin
are serialized under a lock. The daemon itself is single-threaded and
order-preserving, so no request pipelining hazards exist.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

DEFAULT_TIMEOUT_S = 90.0
CONNECT_TIMEOUT_S = 150.0

# Ops whose params are not logged verbatim (values may be long or sensitive).
_REDACT_PARAMS = {"clipboard_set": ("text",)}


class GatewayError(RuntimeError):
    """Raised when an op fails on the daemon side."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class DaemonDied(GatewayError):
    def __init__(self, detail: str = "daemon exited"):
        super().__init__("E_DAEMON", detail)


def _default_daemon() -> Path:
    override = os.environ.get("GATEWAY_RDPUTIL")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "tools" / "rdputil" / "target" / "release" / "rdputil.exe"


class RdpSession:
    """One long-lived RDP session against one target, driven by the daemon."""

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
        cliprdr: bool = True,
        rdpdr: bool = False,
        extra_args: list[str] | None = None,
        extra_env: dict[str, str] | None = None,
        remote_app: dict | None = None,
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
        self.cliprdr = cliprdr
        self.rdpdr = rdpdr
        self.extra_args = extra_args or []
        self.extra_env = dict(extra_env or {})
        # RemoteApp (RAIL) launch request: {"app", "args"?, "workdir"?}. When
        # set, the daemon connects in RemoteApp mode and the session's lifetime
        # is the app's lifetime — the server closes it when the app exits.
        self.remote_app = remote_app

        self.desktop: dict | None = None
        self.status = "starting"
        self.last_sig: str | None = None
        # Connection-ladder code from the daemon's dead event (E_CONN_TARGET /
        # E_AUTH / E_CAPABILITY); None while the connect phase never failed.
        self.connect_code: str | None = None

        self._proc: subprocess.Popen | None = None
        self._stdin_lock = threading.Lock()
        self._pending: dict[int, threading.Event] = {}
        self._results: dict[int, dict] = {}
        self._id_lock = threading.Lock()
        self._next_id = 0
        self._evidence_lock = threading.Lock()
        self._closed = threading.Event()

    # ------------------------------------------------------------------ life

    def start(self) -> None:
        if self._proc is not None:
            raise GatewayError("E_STATE", "session already started")
        argv = [
            str(self.daemon_path),
            "serve",
            "--host", self.host,
            "-u", self.username,
            "--label", self.name,
            "--artifacts-dir", str(self.artifacts_dir.resolve()),
            "--golden-rule", "1" if self.golden_rule else "0",
            *(["--cliprdr"] if self.cliprdr else []),
            *(self.extra_args),
        ]
        if self.rdpdr:
            redirect_root = self.run_dir / "redirect"
            redirect_root.mkdir(exist_ok=True)
            argv += ["--rdpdr", str(redirect_root)]
        env = {**os.environ, "RDPUTIL_PASS": self.password, **self.extra_env}
        if self.cliprdr:
            env["RDPUTIL_CLIPRDR"] = "1"
        if self.remote_app:
            env["RDPUTIL_REMOTE_APP"] = str(self.remote_app["app"])
            if self.remote_app.get("args"):
                env["RDPUTIL_REMOTE_APP_ARGS"] = str(self.remote_app["args"])
            if self.remote_app.get("workdir"):
                env["RDPUTIL_REMOTE_APP_WORKDIR"] = str(self.remote_app["workdir"])
        # Daemon tracing (connection ladder, cliprdr wire events) is the
        # primary diagnostic surface — keep it next to the artifacts.
        self._stderr_file = open(self.artifacts_dir / "daemon_stderr.log", "w", encoding="utf-8", errors="replace")
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            text=True,
            encoding="utf-8",
            env=env,
        )
        threading.Thread(target=self._read_loop, daemon=True).start()
        self.evidence("session_start", {"host": self.host, "user": self.username})

    def close(self) -> None:
        """Graceful quit (daemon sends the disconnect ultimatum), then reap."""
        if self._proc is None:
            return
        try:
            self._send_raw({"id": 0, "op": "q", "p": {}})
        except (BrokenPipeError, OSError):
            pass
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)
        self._stderr_file.close()
        self._proc = None
        self.status = "closed"
        self.evidence("session_close", {})

    @property
    def dead(self) -> bool:
        """True once the daemon is gone or the session ended. A RemoteApp
        session goes dead when its app exits — that is its normal end."""
        return self._closed.is_set() or self.status in ("closed", "dead")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    # ----------------------------------------------------------- wire plumbing

    def _send_raw(self, obj: dict) -> None:
        assert self._proc and self._proc.stdin
        line = json.dumps(obj, ensure_ascii=False)
        with self._stdin_lock:
            self._proc.stdin.write(line + "\n")
            self._proc.stdin.flush()

    def _read_loop(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self.evidence("protocol_error", {"raw": line[:200]})
                continue
            if "ev" in msg:
                self._on_event(msg)
            elif "id" in msg:
                ev = self._pending.pop(msg["id"], None)
                if ev is not None:
                    with self._id_lock:
                        self._results[msg["id"]] = msg
                    ev.set()
        self._closed.set()
        for rid in list(self._pending):
            ev = self._pending.pop(rid, None)
            if ev is not None:
                ev.set()

    def _on_event(self, msg: dict) -> None:
        ev = msg.get("ev")
        if ev == "hello":
            self.desktop = msg.get("desktop")
            self.status = "connecting"
        elif ev == "session":
            self.status = msg.get("state", self.status)
            if self.status == "connected" and msg.get("desktop"):
                self.desktop = msg["desktop"]
            if msg.get("detail") and isinstance(msg["detail"], dict):
                self.last_sig = msg["detail"].get("sig")
                if msg["detail"].get("code"):
                    self.connect_code = msg["detail"]["code"]
        elif ev == "bye":
            self.status = "closed"
            self._closed.set()
        self.evidence(f"event_{ev}", msg)

    # ------------------------------------------------------------------- call

    def wait_connected(self, timeout: float = CONNECT_TIMEOUT_S) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline and not self._closed.is_set():
            if self.status == "connected":
                return
            time.sleep(0.2)
        raise GatewayError(
            self.connect_code or "E_CONN",
            f"session not connected (status={self.status}, sig={self.last_sig})",
        )

    def call(self, op: str, p: dict | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
        """Send one op, wait for its response, return the `r` payload."""
        if self._closed.is_set():
            raise DaemonDied()
        with self._id_lock:
            self._next_id += 1
            rid = self._next_id
            ev: threading.Event = threading.Event()
            self._pending[rid] = ev
        t0 = time.time()
        try:
            self._send_raw({"id": rid, "op": op, "p": p or {}})
        except (BrokenPipeError, OSError) as e:
            self._pending.pop(rid, None)
            raise DaemonDied(f"daemon pipe broken: {e}") from e
        if not ev.wait(timeout):
            self._pending.pop(rid, None)
            raise GatewayError("E_TIMEOUT", f"{op} did not answer within {timeout}s")
        msg = self._results.pop(rid)
        t_ms = int((time.time() - t0) * 1000)
        evidence_p = dict(p or {})
        for key in _REDACT_PARAMS.get(op, ()):  # keep long payloads out of the log
            if key in evidence_p:
                evidence_p[key] = f"<{len(str(evidence_p[key]))} chars>"
        self.evidence(
            f"op_{op}",
            {"p": evidence_p, "ok": bool(msg.get("ok")), "daemon_ms": msg.get("t_ms"), "gateway_ms": t_ms},
        )
        if msg.get("ok"):
            # Merge the flag into the payload so tool-surface callers (which
            # never see the envelope) get a uniform {"ok": true, ...} shape.
            return {"ok": True, **(msg.get("r") or {})}
        err = msg.get("err") or {}
        raise GatewayError(err.get("code", "E_UNKNOWN"), err.get("detail", ""))

    def logged_call(self, op: str, p: dict | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
        """Alias of call(); evidence redaction is applied inside call()."""
        return self.call(op, p, timeout)

    # --------------------------------------------------------------- evidence

    def evidence(self, kind: str, payload: dict) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "vm": self.name, "kind": kind, **payload}
        with self._evidence_lock:
            with open(self.run_dir / "evidence.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
