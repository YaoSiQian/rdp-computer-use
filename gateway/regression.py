"""Profile-keyed regression matrix over the gateway tool surface.

Every case declares which profiles it applies to and runs against a fresh
session pool, so a case that wedges or kills its session cannot poison the
next one. Cases that exercise a known-fatal sequence carry `expected_red`:
the matrix passes when they fail in the documented way and flags an
annotation drift when they suddenly go green — the profile metadata says
these sequences kill the target, and hiding that would be worse than the
crash (report, don't retry; the harness never auto-retries a red).

Usage:
    python -m gateway.regression                    # all profiles, non-skipped cases
    python -m gateway.regression --profiles w7 u22  # subset of targets
    python -m gateway.regression --only oneshot_blind_loop
    python -m gateway.regression --with-disabled    # include default-skipped (xp) cases
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback

from .pool import SessionPool
from .session import GatewayError

RUN_ROOT = "runs/regression"


class SkipCase(Exception):
    """Raised by a case to abort itself without counting as red."""


class Drift(Exception):
    """An expected-red case did not fail: the documented fatal behavior did
    not reproduce on the current surface. Surfaced as a prominent warning
    (the annotation needs re-verification), not as a matrix failure."""


class Case:
    def __init__(self, name: str, profiles: tuple[str, ...], fn, *, expected_red: bool = False,
                 default_skip: bool = False, desc: str = ""):
        self.name = name
        self.profiles = profiles
        self.fn = fn
        self.expected_red = expected_red
        self.default_skip = default_skip
        self.desc = desc


# --------------------------------------------------------------------- cases
# Case bodies receive a bound ToolBox and return a short note; they raise on
# failure (any exception counts as red) and SkipCase when preconditions fail.

def case_connect_state(box) -> str:
    st = box.state()
    if not st.get("ok"):
        raise RuntimeError(f"state not ok: {st}")
    return f"engine={st.get('engine', 'daemon')} status={st.get('status', '?')}"


def case_screenshot_frame(box) -> str:
    obs = box.screenshot()
    lum = obs["mean_lum"]
    if not (0.0 <= lum <= 255.0):
        raise RuntimeError(f"mean_lum out of range: {lum}")
    if obs["distinct"] < 100:
        raise RuntimeError(f"suspiciously few colors: {obs['distinct']}")
    return f"native={obs['native']['w']}x{obs['native']['h']} lum={lum} distinct={obs['distinct']}"


def case_modifier_tap(box) -> str:
    box.key("ctrl")
    box.key("shift")
    return "modifier taps accepted"


def case_click_left(box) -> str:
    st = box.state()
    desktop = box.session.desktop or (st.get("desktop") or {})
    w = int(desktop.get("w", 1024))
    h = int(desktop.get("h", 768))
    box.click(w // 2, h // 2, native=True)
    return f"left click at ({w // 2},{h // 2}) accepted"


def case_clipboard_write(box) -> str:
    """clip_put announces CF_UNICODETEXT to the guest rdpclip; reading back
    our own push is documented to yield an empty format list (delayed
    rendering — data is served when a guest app actually pastes), so the
    assertion here is the accepted announcement, not a get-roundtrip."""
    token = f"gw-regression-{int(time.time())}"
    r = box.clipboard_set(token)
    if not r.get("ok"):
        raise RuntimeError(f"clipboard_set not ok: {r}")
    if int(r.get("chars", 0)) != len(token):
        raise RuntimeError(f"char count mismatch: {r}")
    return f"announcement accepted ({len(token)} chars)"


def case_oneshot_blind_loop(box) -> str:
    """Blind-send -> verify-on-next-frame loop (mines-pipeline isomorphic)."""
    s1 = box.screenshot()
    box.key("super")
    s2 = box.screenshot()
    opened = (abs(s2["mean_lum"] - s1["mean_lum"]) > 3.0
              or abs(s2["distinct"] - s1["distinct"]) > 100)
    if not opened:
        raise RuntimeError(f"overview did not change the frame "
                           f"(dlum={abs(s2['mean_lum'] - s1['mean_lum']):.2f})")
    box.key("esc")
    s3 = box.screenshot()
    closed = abs(s3["mean_lum"] - s1["mean_lum"]) <= 3.0
    if not closed:
        raise RuntimeError(f"frame did not return to baseline "
                           f"(back-dlum={abs(s3['mean_lum'] - s1['mean_lum']):.2f})")
    st = box.state()
    return f"loop verified, orphans_reaped={st.get('orphans_reaped', '?')}"


def case_w7_desktop_menu_esc(box) -> str:
    """EXPECTED-RED annotation under test: desktop context menu + Esc on the
    w7 profile was observed (2026-10-07, drive-mode surface) to end in a
    disconnect ultimatum. The case exposes the desktop, opens the menu for
    real, verifies the documented death signature after Esc — and raises
    Drift when the session survives instead, flagging the annotation as
    stale on the current surface rather than silently passing it.

    Re-verified 2026-10-09 on an interactive desktop: the sequence survives
    on both engines (serve: clean survival; drive: SETERR + channel
    deactivation that reactivates, no ultimatum). The annotation stays until
    the death is re-confirmed or the annotation is formally retired.
    """
    st = box.state()
    desktop = box.session.desktop or (st.get("desktop") or {})
    w = int(desktop.get("w", 1024))
    h = int(desktop.get("h", 768))
    # The desktop sits under whatever the guest left open; minimize all
    # windows so the right-click lands on the desktop and not on a leftover
    # window. Win+M (not Win+D) — Win+D toggles, restoring what a previous
    # run already minimized.
    box.key("win+m")
    time.sleep(1.5)
    base = box.screenshot()  # baseline
    box.click(int(w * 0.75), int(h * 0.6), button="right", native=True)
    time.sleep(1.0)
    menu = box.screenshot()
    opened = (abs(menu["mean_lum"] - base["mean_lum"]) >= 1.0
              or abs(menu["distinct"] - base["distinct"]) >= 50)
    if not opened:
        raise SkipCase("context menu did not open; death sequence not exercised")
    box.key("esc")  # expected to take the session down
    # Death signature: the server answers the Esc with a disconnect
    # ultimatum within seconds; verify instead of assuming.
    deadline = time.time() + 20
    while time.time() < deadline:
        if getattr(box.session, "status", "") in ("dead", "closed"):
            return f"death signature confirmed ({box.session.status})"
        time.sleep(1.0)
    try:
        box.screenshot()
    except GatewayError:
        return "death signature confirmed (session unanswerable)"
    raise Drift("sequence survived: session answerable 20s after esc")


def case_xp_type_burst(box) -> str:
    """EXPECTED-RED annotation under test on the xp profile: input-bearing
    sessions get kicked ~14-20s after the first input (terminate + RST), so
    a long type burst should end in the documented death signature.

    Default-skipped: the xp profile stays gated off until the burst probe
    passes; enabling this case (--with-disabled) is the probe. A session
    still answerable after the kick window raises Drift — the annotation is
    stale on the current surface.
    """
    box.type_text("regression burst " * 40, mode="text")
    deadline = time.time() + 25
    while time.time() < deadline:
        if getattr(box.session, "status", "") in ("dead", "closed"):
            return f"death signature confirmed ({box.session.status})"
        time.sleep(1.0)
    try:
        box.screenshot()
    except GatewayError:
        return "death signature confirmed (session unanswerable)"
    raise Drift("session answerable 25s after burst; kick did not reproduce")


CASES: list[Case] = [
    Case("connect_state", ("w10", "w7", "xp", "u22"), case_connect_state,
         desc="state op answers on every engine"),
    Case("screenshot_frame", ("w10", "w7", "xp", "u22"), case_screenshot_frame,
         desc="frame with sane stats"),
    Case("modifier_tap", ("w10", "w7", "u22"), case_modifier_tap,
         desc="harmless modifier key taps"),
    Case("click_left", ("w10", "w7", "u22"), case_click_left,
         desc="left click at desktop center"),
    Case("clipboard_write", ("w10",), case_clipboard_write,
         desc="clip_put announcement accepted by guest rdpclip"),
    Case("oneshot_blind_loop", ("u22",), case_oneshot_blind_loop,
         desc="u22: blind action verified by next connection's frame"),
    Case("w7_menu_esc_death", ("w7",), case_w7_desktop_menu_esc,
         expected_red=True,
         desc="expected-red probe: desktop context menu + Esc (drift-aware)"),
    Case("xp_type_burst", ("xp",), case_xp_type_burst,
         expected_red=True, default_skip=True,
         desc="KNOWN DEATH RISK: type burst (input_violation source); probe only"),
]


# -------------------------------------------------------------------- runner

def run_case(profile: str, case: Case) -> tuple[str, str]:
    """Returns (verdict, note). Verdicts: GREEN, RED, RED(expected), SKIP, DRIFT."""
    pool = SessionPool(run_root=f"{RUN_ROOT}/{time.strftime('%Y%m%d_%H%M%S')}_{profile}_{case.name}")
    try:
        box = pool.toolbox(profile)
        note = case.fn(box)
        return ("GREEN", note)
    except SkipCase as e:
        return ("SKIP", str(e))
    except Drift as e:
        return ("DRIFT", str(e))
    except Exception as e:  # noqa: BLE001 — any failure is a red by definition
        kind = type(e).__name__
        detail = str(e).replace("\n", " ")[:200]
        if isinstance(e, GatewayError):
            detail = f"{e.code}: {e.detail}"[:200]
        return ("RED", f"{kind}: {detail}")
    finally:
        try:
            pool.close()
        except Exception:  # noqa: BLE001 — closing a dead session must not mask the verdict
            traceback.print_exc()


def main() -> int:
    ap = argparse.ArgumentParser(description="profile-keyed gateway regression matrix")
    ap.add_argument("--profiles", nargs="*", default=None, help="target profile names (default: all)")
    ap.add_argument("--only", nargs="*", default=None, help="case names to run (default: all)")
    ap.add_argument("--with-disabled", action="store_true",
                    help="include default-skipped cases (xp burst probe)")
    args = ap.parse_args()

    from .pool import load_profiles

    profiles = args.profiles or list(load_profiles())
    cases = [c for c in CASES
             if (args.only is None or c.name in args.only)
             and (args.with_disabled or not c.default_skip)]

    results: list[tuple[str, str, str, str]] = []  # profile, case, verdict, note
    print(f"{'profile':<10} {'case':<22} verdict")
    for profile in profiles:
        for case in cases:
            if profile not in case.profiles:
                continue
            if case.default_skip and not args.with_disabled:
                results.append((profile, case.name, "SKIP", "default-skipped (gated profile)"))
                print(f"{profile:<10} {case.name:<22} SKIP (default-skipped)")
                continue
            verdict, note = run_case(profile, case)
            if case.expected_red and verdict == "RED":
                verdict = "RED(expected)"
            results.append((profile, case.name, verdict, note))
            print(f"{profile:<10} {case.name:<22} {verdict}  {note}", flush=True)

    print("\nmatrix summary:")
    failed = False
    for profile, name, verdict, note in results:
        if verdict in ("GREEN", "RED(expected)", "SKIP"):
            mark = "ok"
        elif verdict == "DRIFT":
            mark = "WARN"
        else:
            mark = "FAIL"
        if mark == "FAIL":
            failed = True
        print(f"  [{mark}] {profile}/{name}: {verdict} — {note}")
    print("MATRIX:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
