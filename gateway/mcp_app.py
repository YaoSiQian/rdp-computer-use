"""MCP stdio surface: same tools, one target per server process.

Run: python -m gateway --mcp --profile win10
The screenshot tool returns the scaled image plus JSON metadata; the rest
return JSON strings.
"""

from __future__ import annotations

import base64
import json

from mcp.server.fastmcp import FastMCP, Image

from .pool import SessionPool
from .session import GatewayError


def create_mcp(pool: SessionPool, profile: str) -> FastMCP:
    mcp = FastMCP(f"rdp-{profile}")


    def _box():
        return pool.toolbox(profile)


    def _json(obj) -> str:
        return json.dumps(obj, ensure_ascii=False)


    @mcp.tool()
    async def start_app(app: str, args: str | None = None) -> str:
        """Start a task-scoped RemoteApp session that launches `app` (RAIL:
        only the app's window is on the screen, no desktop).

        Lifecycle rules:
        - This disconnects the current desktop session on the target; there is
          one session per target, so expect any desktop state to be gone.
        - The session ends when the app exits — that is the normal lifecycle,
          not a failure. After it ends, the next tool call gets a fresh
          desktop session automatically.
        - Use start_app when the whole task lives inside one application
          (smaller observation, deterministic start/exit boundaries). Use the
          default desktop session when the task spans several apps, the shell,
          or unknown launch points.
        - The guest must allow the program as a RemoteApp (allow-list or the
          fAllowUnlistedRemotePrograms policy), otherwise E_APP_START is
          returned and the previous session mode is restored on next call.
        """
        try:
            return _json(pool.start_app(profile, app, args))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def probe() -> str:
        """Re-run target detection: connection ladder, frame
        mode, RemoteApp capability. Merges the result into the target's
        detected_profile, which gates engine choice and start_app.

        Use after the target's configuration changed (policy edits, server
        upgrades, role switches) or when start_app/behaviour disagrees with
        what the profile claims."""
        try:
            return _json(pool.probe(profile))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})
        except (KeyError, RuntimeError) as e:
            return _json({"ok": False, "code": "E_CONFIG", "detail": str(e)})


    @mcp.tool()
    async def screenshot(wait_stable_ms: int = 1500, tol_px: int = 64) -> list:
        """Take a screenshot of the remote desktop.

        Returns the image (scaled to fit 1024x768) plus geometry metadata:
        `scale` maps observation coordinates onto native ones — multiply model
        x/y by 1/scale before calling click/move with native=true, or just use
        observation coordinates directly (they are mapped automatically).
        """
        try:
            obs = _box().screenshot(wait_stable_ms, tol_px)
        except GatewayError as e:
            return [_json({"ok": False, "code": e.code, "detail": e.detail})]
        png_bytes = base64.b64decode(obs.pop("image_base64"))
        meta = _json(obs)
        return [Image(data=png_bytes, format="png"), meta]


    @mcp.tool()
    async def click(x: int, y: int, button: str = "left", double: bool = False, native: bool = False) -> str:
        """Click at (x, y). Coordinates are in the last screenshot's scaled
        space unless native=true. `button` is left/right/middle."""
        try:
            return _json(_box().click(x, y, button, double, native))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def move(x: int, y: int, native: bool = False) -> str:
        """Move the pointer without clicking."""
        try:
            return _json(_box().move(x, y, native))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def type_text(text: str) -> str:
        """Type text into the focused window (US layout)."""
        try:
            return _json(_box().type_text(text))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def key(combo: str) -> str:
        """Press a key combo, e.g. "enter", "ctrl+shift+esc", "alt+tab"."""
        try:
            return _json(_box().key(combo))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def wait(ms: int) -> str:
        """Sleep on the guest-side pump so desktop effects settle."""
        try:
            return _json(_box().wait(ms))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def scroll(delta: int, x: int | None = None, y: int | None = None) -> str:
        """Turn the mouse wheel: negative `delta` scrolls down, positive up
        (rotation units, 120 per physical notch, |delta| <= 1200). Pass x/y
        to move the pointer there first so the wheel lands on that window."""
        try:
            return _json(_box().scroll(delta, x, y))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def resize(w: int, h: int) -> str:
        """Resize the remote desktop to w×h through the display-control
        channel (inline reactivation). Requires the target profile to opt
        into the display-control channel; targets without it refuse this
        (E_UNSUPPORTED)."""
        try:
            return _json(_box().resize(w, h))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def clipboard_get() -> str:
        """Read the guest clipboard as text."""
        try:
            return _json(_box().clipboard_get())
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def clipboard_set(text: str) -> str:
        """Write text to the guest clipboard; follow with key "ctrl+v" to paste."""
        try:
            return _json(_box().clipboard_set(text))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def file_push(local_path: str, guest_name: str | None = None) -> str:
        """Copy a host file into the redirected drive share; the guest reads
        it at \\\\tsclient\\tools\\<guest_name>."""
        try:
            return _json(_box().file_push(local_path, guest_name))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def file_pull(guest_path: str, local_path: str | None = None) -> str:
        """Read a file out of the redirected drive share and store it on the
        host next to the session evidence."""
        try:
            return _json(_box().file_pull(guest_path, local_path))
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    @mcp.tool()
    async def state() -> str:
        """Session state: uptime, input counters, last death signature.
        RemoteApp sessions (see start_app) also report session_mode,
        rail_exec and app_window."""
        try:
            return _json(_box().state())
        except GatewayError as e:
            return _json({"ok": False, "code": e.code, "detail": e.detail})


    return mcp
