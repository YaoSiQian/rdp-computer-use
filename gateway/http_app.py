"""HTTP REST surface (OSWorld-flavoured): one route per tool, per target.

Run: python -m gateway --http --port 8080
All tool routes return JSON; tool-level failures come back as
{"ok": false, "code": ..., "detail": ...} so a model-driven client can read
the error code exactly like it reads tool output. Request bodies are parsed
manually (no pydantic) to stay version-agnostic.
"""

from __future__ import annotations

import base64

from fastapi import FastAPI, HTTPException, Request, Response

from .pool import SessionPool
from .session import GatewayError


def create_app(pool: SessionPool) -> FastAPI:
    app = FastAPI(title="rdp-gateway", version="0.1.0")

    def _box(name: str):
        try:
            return pool.toolbox(name)
        except GatewayError as e:
            raise HTTPException(status_code=503, detail=f"{e.code}: {e.detail}") from e
        except RuntimeError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    def _run(name: str, fn) -> dict:
        try:
            return {"ok": True, **fn()}
        except GatewayError as e:
            return {"ok": False, "code": e.code, "detail": e.detail}

    async def _body(req: Request) -> dict:
        try:
            raw = await req.json()
            return raw if isinstance(raw, dict) else {}
        except Exception:
            return {}

    @app.get("/status")
    def status() -> dict:
        return pool.status()

    @app.post("/vm/{name}/screenshot")
    async def screenshot(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).screenshot(int(p.get("wait_stable_ms", 1500)), int(p.get("tol_px", 64))))

    @app.post("/vm/{name}/click")
    async def click(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(
            name,
            lambda: _box(name).click(
                int(p.get("x", 0)), int(p.get("y", 0)),
                str(p.get("button", "left")), bool(p.get("double", False)), bool(p.get("native", False)),
            ),
        )

    @app.post("/vm/{name}/move")
    async def move(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).move(int(p.get("x", 0)), int(p.get("y", 0)), bool(p.get("native", False))))

    @app.post("/vm/{name}/type")
    async def type_text(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).type_text(str(p.get("text", ""))))

    @app.post("/vm/{name}/key")
    async def key(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).key(str(p.get("combo", ""))))

    @app.post("/vm/{name}/wait")
    async def wait(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).wait(int(p.get("ms", 500))))

    @app.get("/vm/{name}/clipboard")
    def clipboard_get(name: str) -> dict:
        return _run(name, lambda: _box(name).clipboard_get())

    @app.post("/vm/{name}/clipboard")
    async def clipboard_set(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).clipboard_set(str(p.get("text", ""))))

    @app.post("/vm/{name}/resize")
    async def resize(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).resize(int(p.get("w", 1280)), int(p.get("h", 1024))))

    @app.post("/vm/{name}/file_push")
    async def file_push(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).file_push(str(p.get("local_path", "")), p.get("guest_name")))

    @app.post("/vm/{name}/file_pull")
    async def file_pull(name: str, req: Request) -> dict:
        p = await _body(req)
        return _run(name, lambda: _box(name).file_pull(str(p.get("guest_path", "")), p.get("local_path")))

    @app.post("/vm/{name}/app/start")
    async def app_start(name: str, req: Request) -> dict:
        """Swap the target's session over to a RemoteApp (RAIL) session that
        launches `app`; it ends when the app exits. Body: {"app": "...",
        "args"?, "workdir"?}."""
        p = await _body(req)
        app = str(p.get("app", "")).strip()
        if not app:
            return {"ok": False, "code": "E_ARGS", "detail": "app is required"}
        try:
            return pool.start_app(name, app, p.get("args"), p.get("workdir"))
        except GatewayError as e:
            return {"ok": False, "code": e.code, "detail": e.detail}
        except KeyError as e:
            return {"ok": False, "code": "E_ARGS", "detail": str(e)}
        except RuntimeError as e:
            return {"ok": False, "code": "E_CONFIG", "detail": str(e)}

    @app.post("/vm/{name}/probe")
    def probe(name: str) -> dict:
        """Run the §2.8 detection pipeline; rewrites detected_profile."""
        try:
            return pool.probe(name)
        except GatewayError as e:
            return {"ok": False, "code": e.code, "detail": e.detail}
        except KeyError as e:
            return {"ok": False, "code": "E_ARGS", "detail": str(e)}
        except RuntimeError as e:
            return {"ok": False, "code": "E_CONFIG", "detail": str(e)}

    @app.get("/vm/{name}/state")
    def state(name: str) -> dict:
        return _run(name, lambda: _box(name).state())

    @app.post("/vm/{name}/close")
    def close(name: str) -> dict:
        pool.close(name)
        return {"ok": True}

    @app.get("/vm/{name}/screenshot/png")
    def screenshot_png(name: str, wait_stable_ms: int = 1500, tol_px: int = 64):
        try:
            obs = _box(name).screenshot(wait_stable_ms, tol_px)
        except GatewayError as e:
            raise HTTPException(status_code=503, detail=f"{e.code}: {e.detail}") from e
        return Response(content=base64.b64decode(obs["image_base64"]), media_type="image/png")

    return app
