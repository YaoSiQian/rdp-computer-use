# rdp-computer-use

[![build-rdputil](https://github.com/YaoSiQian/rdp-computer-use/actions/workflows/build-rdputil.yml/badge.svg)](https://github.com/YaoSiQian/rdp-computer-use/actions/workflows/build-rdputil.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Turn any RDP-reachable Windows machine into a computer-use environment for
AI agents** — with screenshots, mouse/keyboard control, clipboard sync, file
transfer, and task-scoped RemoteApps, exposed over MCP or HTTP.

简体中文文档：[README-zh_CN.md](README-zh_CN.md)

## Why

Cloud computer-use sandboxes are heavy and Linux-only; real work happens on
Windows. rdp-computer-use reconnects agents to ordinary Windows machines over
the protocol every Windows box already speaks — RDP — with a server-side-free
design: nothing is installed on the target beyond what RDP provides natively.

- **Observe**: pixel screenshots with stable-frame detection and metadata
  (native/scaled sizes, luminance, change stats).
- **Act**: mouse click/move, keyboard text and combos, scrolling, resize —
  with reconnection and session-keepalive handled for you.
- **Exchange**: bidirectional clipboard, plus file push/pull through native
  RDP drive redirection (`\\tsclient\...`) — no extra services on the target.
- **Scope**: run the whole desktop, or a single RemoteApp (RAIL) when a task
  lives inside one application.

## Architecture

```
agent harness (Claude Code / Codex / OpenCode / ZCode / any MCP client)
        │  MCP over stdio            HTTP REST
        ▼                            ▼
┌──────────────────────  gateway (Python)  ─────────────────────┐
│  profiles · session pool · screenshot pipeline · toolboxes    │
└──────────────────────────────┬────────────────────────────────┘
                               │ spawns & supervises
                               ▼
                      rdputil (Rust + IronRDP)
                               │ RDP (TLS/CredSSP, cliprdr, rdpdr,
                               │ rdpsnd, RAIL, display control)
                               ▼
                     Windows target (XP … 11), or xrdp
```

| Component | Language | Role |
| --- | --- | --- |
| `gateway/` | Python 3.10+ | MCP/HTTP server, session pool, observation pipeline |
| `tools/rdputil/` | Rust | long-lived RDP client daemon (input, clipboard, files, RAIL) |

The Rust client consumes [IronRDP](https://github.com/Devolutions/IronRDP)
from a public git source (see `tools/rdputil/Cargo.toml` for why).

## Quickstart

Prerequisites: Rust toolchain (1.85+), Python 3.10+, and a target machine
with RDP enabled and an account that can log in over RDP.

```bash
git clone https://github.com/YaoSiQian/rdp-computer-use.git
cd rdp-computer-use

# 1. Build the client daemon (first build takes a few minutes)
cargo build --release --manifest-path tools/rdputil/Cargo.toml

# 2. Install gateway dependencies
pip install -r requirements.txt

# 3. Configure a target (never commit this file)
cp gateway/profiles.sample.json gateway/profiles.json
```

Edit `gateway/profiles.json`:

```json
{
  "profiles": {
    "mypc": {
      "host": "203.0.113.10",
      "username": "operator",
      "password_env": "MYPC_PASS",
      "rdpdr": true,
      "display_control": true
    }
  }
}
```

The password is read from the environment variable named by `password_env`:

```bash
export MYPC_PASS='...'
python -m gateway --mcp --profile mypc
```

## Wiring it into an agent harness

The gateway is a standard MCP stdio server, so it plugs into every harness
that supports MCP. Launch command (run from the repository directory;
use absolute paths in harness configs):

```
python -m gateway --mcp --profile mypc
```

| Harness | Where to configure |
| --- | --- |
| Claude Code / ZCode | `mcpServers` in settings, or install the bundled skill (below) |
| Codex CLI | `mcp_servers` in `config.toml` |
| OpenCode | `mcp` section of `opencode.json` |
| Anything MCP | `python -m gateway --mcp --profile <name>` over stdio |

**Agent skill**: [`skills/rdp-computer-use/SKILL.md`](skills/rdp-computer-use/SKILL.md)
teaches agents the operational loop (observe → act → confirm, file transfer,
RemoteApp lifecycle, error recovery). Copy or symlink it into your harness's
skill directory (e.g. `~/.claude/skills/rdp-computer-use/`), or point
harnesses that read `AGENTS.md` at this repository — the file links the skill
and the usage manual for you.

## HTTP mode

```bash
python -m gateway --http --port 8080
# POST /vm/mypc/screenshot · /click · /type · /key · /clipboard
# POST /vm/mypc/file_push · /file_pull · /app/start · /probe
# GET  /vm/mypc/state · /vm/mypc/screenshot/png
```

Full endpoint and tool reference: [docs/USAGE.md](docs/USAGE.md).

## Platform support

| | Status |
| --- | --- |
| Windows client (build + run) | supported, CI-built on every push |
| Server targets | Windows (XP → 11) over RDP; xrdp via the `oneshot` engine |
| Linux/macOS client | planned — the input/clipboard stack is portable, drive redirection needs the nix rdpdr backend |

Prebuilt Windows binaries are attached to releases and every CI run on the
[Actions](https://github.com/YaoSiQian/rdp-computer-use/actions) tab
(artifact `rdputil-windows-x64`).

## Security notes

- The gateway holds RDP credentials in memory only; profiles reference
  environment variables, and `gateway/profiles.json`, `runs*/`, and
  `experiments/` are gitignored.
- Any RDP login grants full control of the target — use dedicated accounts
  on machines you are authorized to automate.
- The client keeps a session alive and reconnects automatically; be aware
  that connecting will kick an interactive console session where the server
  is configured for single-session RDP.

## License

[MIT](LICENSE)
