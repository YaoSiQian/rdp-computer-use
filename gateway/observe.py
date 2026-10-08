"""Observation pipeline: native PNG -> model-sized base64 image + metadata.

The daemon stores full-resolution PNGs and returns per-frame statistics
(mean luminance, distinct-color count) so callers never need to decode pixels
themselves. For the model, the PNG is additionally rescaled to fit the XGA
box (1024x768) and returned as base64; the recorded scale factor maps model
coordinates back to native desktop coordinates for input ops.
"""

from __future__ import annotations

import base64
import io
import json

from PIL import Image

XGA_W, XGA_H = 1024, 768


def fit_scale(native_w: int, native_h: int, box_w: int = XGA_W, box_h: int = XGA_H) -> float:
    """Uniform scale <= 1 that fits the native frame into the box."""
    return min(box_w / native_w, box_h / native_h, 1.0)


def observe(png_path: str, meta: dict) -> dict:
    """Build the model-facing observation from one daemon screenshot result.

    `meta` is the daemon's screenshot payload ({png, mean_lum, distinct, w, h,
    stable}). Returns the observation dict with base64 image and geometry.
    """
    with open(png_path, "rb") as f:
        native_bytes = f.read()
    img = Image.open(io.BytesIO(native_bytes))
    native_w, native_h = img.size
    scale = fit_scale(native_w, native_h)
    scaled_w, scaled_h = round(native_w * scale), round(native_h * scale)
    if scale < 1.0:
        img = img.convert("RGB").resize((scaled_w, scaled_h), Image.LANCZOS)
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format="PNG")

    return {
        "image_base64": base64.b64encode(buf.getvalue()).decode("ascii"),
        "format": "image/png",
        "native": {"w": native_w, "h": native_h},
        "scaled": {"w": scaled_w, "h": scaled_h},
        "scale": scale,
        "mean_lum": meta.get("mean_lum"),
        "distinct": meta.get("distinct"),
        "stable": meta.get("stable"),
        "png": png_path,
    }


def to_native(point: dict, obs_scale: float) -> dict:
    """Map model-space coordinates to native desktop coordinates."""
    return {"x": int(round(point["x"] / obs_scale)), "y": int(round(point["y"] / obs_scale))}


def stats_only(png_path: str) -> dict:
    """Side-channel stats for callers that do not need the image."""
    with open(png_path, "rb") as f:
        img = Image.open(f)
        return {"w": img.size[0], "h": img.size[1], "bytes": len(png_path)}


def dump_observation(obs: dict) -> str:
    """Compact JSON for protocol payloads (image kept inline)."""
    return json.dumps(obs, ensure_ascii=False)
