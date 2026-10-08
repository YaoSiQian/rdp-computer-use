"""Shared tool implementations behind both protocol surfaces.

Tools take model-friendly parameters (coordinates in the scaled observation
space) and map them back to native desktop coordinates using the scale of the
most recent screenshot taken through this session. The screenshot tool itself
returns the base64 observation plus geometry, so a model can always reason
about what it sees and where it clicks.
"""

from __future__ import annotations

from .observe import observe, to_native
from .session import GatewayError, RdpSession


class ToolBox:
    """Binds a session to the v1 tool surface (design doc §工具面)."""

    def __init__(self, session: RdpSession):
        self.session = session
        self.last_scale: float = 1.0

    # ------------------------------------------------------------- observation

    def screenshot(self, wait_stable_ms: int = 1500, tol_px: int = 64) -> dict:
        r = self.session.call("screenshot", {"wait_stable_ms": wait_stable_ms, "tol_px": tol_px}, timeout=120)
        obs = observe(r["png"], r)
        self.last_scale = obs["scale"]
        self.session.evidence("observe", {"png": r["png"], "scale": obs["scale"]})
        return obs

    # ------------------------------------------------------------------ input

    def _map_point(self, x: int, y: int, native: bool) -> dict:
        if native:
            return {"x": int(x), "y": int(y)}
        return to_native({"x": x, "y": y}, self.last_scale)

    def click(self, x: int, y: int, button: str = "left", double: bool = False, native: bool = False) -> dict:
        p = self._map_point(x, y, native)
        p.update({"button": button, "double": double})
        r = self.session.call("click", p)
        return self._post_input(r, "click")

    def move(self, x: int, y: int, native: bool = False) -> dict:
        r = self.session.call("move", self._map_point(x, y, native))
        return self._post_input(r, "move")

    def type_text(self, text: str, mode: str = "text") -> dict:
        r = self.session.call("type", {"text": text, "mode": mode}, timeout=300)
        return self._post_input(r, "type")

    def key(self, combo: str) -> dict:
        r = self.session.call("key", {"combo": combo})
        return self._post_input(r, "key")

    def scroll(self, delta: int, x: int | None = None, y: int | None = None) -> dict:
        p: dict = {"delta": delta}
        if x is not None and y is not None:
            p.update(self._map_point(x, y, False))
        return self.session.call("scroll", p)

    def wait(self, ms: int) -> dict:
        return self.session.call("wait", {"ms": ms}, timeout=ms / 1000 + 30)

    # -------------------------------------------------------------- clipboard

    def clipboard_get(self) -> dict:
        r = self.session.call("clipboard_get", {}, timeout=60)
        return {"ok": True, "text": r.get("text", "")}

    def clipboard_set(self, text: str) -> dict:
        return self.session.call("clipboard_set", {"text": text}, timeout=60)

    # ----------------------------------------------------------------- display

    def resize(self, w: int, h: int) -> dict:
        return self.session.call("resize", {"w": w, "h": h}, timeout=120)

    def state(self) -> dict:
        return self.session.call("state", {})

    def refresh(self) -> dict:
        return self.session.call("refresh", {}, timeout=60)

    # ------------------------------------------------------------------ files

    def file_push(self, local_path: str, guest_name: str | None = None) -> dict:
        raise GatewayError("E_UNSUPPORTED", "file_push arrives with the rdpdr milestone (M3)")

    def file_pull(self, guest_path: str) -> dict:
        raise GatewayError("E_UNSUPPORTED", "file_pull arrives with the rdpdr milestone (M3)")

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _post_input(r: dict, op: str) -> dict:
        out = {"op": op, **r}
        out.pop("png", None)
        return out
