"""Gateway entry point.

    python -m gateway --list-profiles
    python -m gateway --mcp --profile win10        # MCP over stdio
    python -m gateway --http --port 8080           # HTTP REST, all profiles
"""

from __future__ import annotations

import argparse
import json
import sys

from .pool import SessionPool, load_profiles


def main() -> int:
    ap = argparse.ArgumentParser(prog="gateway")
    ap.add_argument("--mcp", action="store_true", help="serve MCP over stdio")
    ap.add_argument("--http", action="store_true", help="serve HTTP REST")
    ap.add_argument("--profile", help="target name for --mcp")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--daemon", help="path to the rdputil daemon binary")
    ap.add_argument("--no-golden-rule", action="store_true")
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("--probe", metavar="NAME", help="run detection against one target, then exit")
    args = ap.parse_args()

    if args.list_profiles:
        print(json.dumps({n: {"username": p["username"], "host": p["host"]} for n, p in load_profiles().items()}, indent=2))
        return 0

    if args.probe:
        pool = SessionPool(daemon_path=args.daemon)
        try:
            result = pool.probe(args.probe)
        except KeyError as e:
            print(json.dumps({"ok": False, "code": "E_ARGS", "detail": str(e)}, ensure_ascii=False))
            return 2
        except RuntimeError as e:
            print(json.dumps({"ok": False, "code": "E_CONFIG", "detail": str(e)}, ensure_ascii=False))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 1

    if args.mcp and not args.profile:
        ap.error("--mcp requires --profile")
    if not (args.mcp or args.http or args.list_profiles):
        ap.error("choose --mcp or --http")

    pool = SessionPool(daemon_path=args.daemon)

    if args.mcp:
        from .mcp_app import create_mcp

        # The pool pre-connects on first toolbox(); MCP tools connect lazily
        # per call so a dead daemon surfaces as a tool error, not a crash.
        mcp = create_mcp(pool, args.profile)

        @mcp.tool()
        async def close() -> str:
            """Shut the session down gracefully."""
            pool.close(args.profile)
            return '{"ok": true}'

        mcp.run()
        return 0

    if args.http:
        import uvicorn

        from .http_app import create_app

        uvicorn.run(create_app(pool), host=args.host, port=args.port, log_level="info")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
