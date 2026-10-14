# AGENTS.md

Instructions for coding agents (Codex, OpenCode, ZCode, Claude Code, ...)
working in this repository.

## What this repository is

rdp-computer-use turns a Windows (and other RCP-capable RDP) target machine
into a computer-use environment for AI agents:

- `gateway/` - a Python **MCP (stdio)** and **HTTP REST** server that owns
  long-lived RDP sessions and exposes observe/act tools: screenshot,
  click/move/type/key/scroll, clipboard sync, file push/pull (drive
  redirection), RemoteApp lifecycle (RAIL), display resize.
- `tools/rdputil/` - the **Rust RDP client daemon** the gateway drives.
  Built on IronRDP; see the crate's `Cargo.toml` for the exact source.
- `skills/rdp-computer-use/SKILL.md` - the operational skill for *using*
  the tools from an agent harness (the entry point for Claude Code and
  other Agent-Skills-compatible harnesses).
- `docs/USAGE.md` - full user manual (profiles, tool reference, HTTP API,
  troubleshooting).

## Setup (from a clean clone)

```bash
# 1. Client daemon (Rust, currently targets Windows hosts)
cargo build --release --manifest-path tools/rdputil/Cargo.toml

# 2. Gateway dependencies (Python 3.10+)
pip install -r requirements.txt

# 3. Targets: copy the sample and edit (never commit profiles.json)
cp gateway/profiles.sample.json gateway/profiles.json
#    each profile's password comes from an environment variable named in
#    the profile ("password_env"), never from the file itself
```

The gateway locates the daemon at
`tools/rdputil/target/release/rdputil[.exe]`; override with the
`GATEWAY_RDPUTIL` environment variable.

## Running

```bash
python -m gateway --mcp --profile <name>   # MCP over stdio (one profile)
python -m gateway --http --port 8080       # HTTP REST (all profiles)
python -m gateway --list-profiles
python -m gateway --probe <name>           # target reachability check
```

## Conventions and hard rules

- **Never commit** target-specific facts: `gateway/profiles.json`, run
  output under `runs*/`, captures, and any real host/IP/credential. The
  sample profile uses placeholders only.
- New Python is 3.10+-compatible stdlib style matching the existing
  modules; new Rust follows `cargo fmt`/`cargo clippy` cleanliness.
- Functional changes to the gateway are exercised through
  `experiments/`-style scripts locally, but experiments are **not**
  committed; the commit is code only, with a conventional
  (`type(scope): summary`) message.
- The Rust client consumes IronRDP from a public git source (see
  `tools/rdputil/Cargo.toml`). Keep it buildable from a clean clone
  without any machine-local configuration.
