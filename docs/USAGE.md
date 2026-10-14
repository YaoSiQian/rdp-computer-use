# rdp-computer-use — Usage Manual

Everything a human or an agent needs to install, configure, and operate the
gateway. For the agent-facing operational loop, see
[`skills/rdp-computer-use/SKILL.md`](../skills/rdp-computer-use/SKILL.md).

- [1. Components](#1-components)
- [2. Installation](#2-installation)
- [3. Target profiles](#3-target-profiles)
- [4. Running the gateway](#4-running-the-gateway)
- [5. MCP tool reference](#5-mcp-tool-reference)
- [6. HTTP REST reference](#6-http-rest-reference)
- [7. Error codes](#7-error-codes)
- [8. Troubleshooting](#8-troubleshooting)
- [9. CI artifacts](#9-ci-artifacts)

## 1. Components

```
harness ──MCP/HTTP──▶ gateway (Python) ──spawn/supervise──▶ rdputil (Rust) ──RDP──▶ target
```

- **gateway** owns the tool surface and session bookkeeping. It spawns one
  `rdputil serve` process per session, speaks the client protocol over
  stdio/JSON, and renders screenshots (PNG + metadata).
- **rdputil** is the RDP client: TLS/CredSSP authentication, static channels
  (cliprdr, rdpdr, rdpsnd, RAIL, display control), automatic reconnect, and
  standalone one-shot commands (`screenshot`, `mouse`, `key`) for scripting
  without the gateway.

## 2. Installation

### 2.1 Client daemon (Rust)

```bash
cargo build --release --manifest-path tools/rdputil/Cargo.toml
```

- First build takes a few minutes (the IronRDP tree is fetched from a public
  git source; see `tools/rdputil/Cargo.toml` for the exact pins and why).
- Runs on Windows (GitHub CI builds it on every push). The gateway picks the
  binary from `tools/rdputil/target/release/rdputil[.exe]` according to the
  host OS; override with `GATEWAY_RDPUTIL=/path/to/binary`.
- Standalone usage without the gateway:

```bash
rdputil screenshot --host <host> -u <user> -p <pass> -o out.png
rdputil mouse --host <host> -u <user> -p <pass> --x 640 --y 512 --action click -o after.png
rdputil key --host <host> -u <user> -p <pass> --text "hello"
```

### 2.2 Gateway (Python)

```bash
pip install -r requirements.txt    # mcp, fastapi, uvicorn, pillow (Python 3.10+)
```

## 3. Target profiles

`gateway/profiles.json` (gitignored; create from
`gateway/profiles.sample.json`) defines every connectable machine:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `host` | str | required | target hostname or IP |
| `username` | str | required | RDP login user |
| `password_env` | str | `GATEWAY_<NAME>_PASS` | env var holding the password; the file itself never contains secrets |
| `rdp_file` | str | - | import connection facts from an `.rdp` file (see below) |
| `rdpdr` | bool | `false` | enable drive redirection (file push/pull as `\\tsclient\<share>`) |
| `display_control` | bool | `false` | enable `resize` via the display-control channel |
| `engine` | str | `daemon` | `oneshot` for targets that dislike long-lived sessions (e.g. xrdp) |
| `desktop_size` | [w,h] | server default | requested resolution at connect |
| `retry_attempts` / `retry_interval_s` | int/float | `3` / `15` | connect retry policy (oneshot engine) |

The sample ships a placeholder profile per common target type. Passwords are
exported before starting the gateway:

```bash
export GATEWAY_MYPC_PASS='...'
```

### 3.1 Importing .rdp files

An entry may point at an `.rdp` file (mstsc "Save As", AVD portal download,
hand-written) instead of repeating its connection facts:

```json
{"mypc": {"rdp_file": "connections/mypc.rdp", "rdpdr": true}}
```

The file is the connection-capability base; the keys written in the profile
entry are the orchestration overlay and win on conflict. Passwords always
resolve from `password_env` — never from the file. The import maps
`full address` (with port split), `server port`, `username`, `domain`,
`desktopwidth`/`desktopheight` (initial canvas), `redirectclipboard:i:0`
(disables the clipboard channel) and `drivestoredirect` (enables drive
redirection against the gateway's dedicated redirect root — never the drives
the file lists). Documented properties the daemon does not implement
(multimon, printer/smart-card redirection, audio, RemoteApp-at-connect, ...)
are accepted as no-ops and reported, and the profile keys that would demand
unsupported machinery are rejected with a clear error at startup: DPAPI
`password 51:b` blobs, `gatewayhostname` (RD Gateway), `kdcproxyname`, and
Entra ID auth flags (`enablerdsaadauth`, `targetisaadjoined:i:1`).

## 4. Running the gateway

```bash
python -m gateway --list-profiles          # sanity-check the config
python -m gateway --probe mypc             # reachability/protocol check
python -m gateway --mcp --profile mypc     # MCP over stdio, one target
python -m gateway --http --port 8080       # HTTP REST, all profiles
```

- MCP mode serves one profile per process; the harness config decides which
  targets an agent can see.
- HTTP mode exposes every profile; prefix each route with the profile name
  (see section 6).
- Sessions connect lazily on first use and reconnect automatically after
  network drops; `close` shuts the session down deliberately.

## 5. MCP tool reference

All tools return JSON strings; `screenshot` also returns the image.

| Tool | Signature | Notes |
| --- | --- | --- |
| `screenshot` | `wait_stable_ms=1500, tol_px=64` | PNG + metadata (`native`, `scaled`, `scale`, `mean_lum`, `distinct`, `stable`); waits for a stable frame |
| `click` | `x, y, button="left", double=false, native=false` | coordinates in screenshot pixels unless `native` |
| `move` | `x, y, native=false` | pointer move only |
| `type_text` | `text` | Unicode text input; use `key` for combos |
| `key` | `combo` | e.g. `enter`, `win+r`, `ctrl+shift+esc`, `alt+tab` |
| `scroll` | `delta, x?, y?` | positive delta scrolls down |
| `wait` | `ms` | sleep on the session; use between act and observe |
| `resize` | `w, h` | needs `display_control: true`; first frame after may be blank |
| `clipboard_get` / `clipboard_set` | `()` / `(text)` | bidirectional host↔guest clipboard |
| `file_push` | `local_path, guest_name?` | host → guest via `\\tsclient\<share>`; returns the guest path |
| `file_pull` | `guest_path, local_path?` | guest → host copy |
| `start_app` | `app, args?` | RAIL RemoteApp; tears down the desktop session; ends when the app exits |
| `state` | `()` | connection age, desktop size, app window id, input counters |
| `probe` | `()` | slow detection ladder; for diagnosing, not the main loop |
| `close` | `()` | graceful session shutdown (auto-registered in MCP mode) |

The canonical agent loop — screenshot → act → screenshot — and the
RemoteApp/file-transfer semantics are documented in the
[skill](../skills/rdp-computer-use/SKILL.md).

## 6. HTTP REST reference

All routes are profile-scoped (`/vm/{name}/...`); bodies are JSON.

| Method | Route | Body | Result |
| --- | --- | --- | --- |
| GET | `/status` | — | profiles and session states |
| POST | `/vm/{name}/screenshot` | `{wait_stable_ms?, tol_px?}` | PNG image + metadata |
| GET | `/vm/{name}/screenshot/png` | — | raw PNG |
| POST | `/vm/{name}/click` | `{x, y, button?, double?, native?}` | ack |
| POST | `/vm/{name}/move` | `{x, y, native?}` | ack |
| POST | `/vm/{name}/type` | `{text}` | ack |
| POST | `/vm/{name}/key` | `{combo}` | ack |
| POST | `/vm/{name}/wait` | `{ms}` | ack |
| GET | `/vm/{name}/clipboard` | — | `{ok, text}` |
| POST | `/vm/{name}/clipboard` | `{text}` | ack |
| POST | `/vm/{name}/resize` | `{w, h}` | new size |
| POST | `/vm/{name}/file_push` | `{local_path, guest_name?}` | guest path |
| POST | `/vm/{name}/file_pull` | `{guest_path, local_path?}` | host path |
| POST | `/vm/{name}/app/start` | `{app, args?}` | RAIL session ack |
| POST | `/vm/{name}/probe` | — | detection report |
| GET | `/vm/{name}/state` | — | session state |
| POST | `/vm/{name}/close` | — | session teardown |

## 7. Error codes

Every failure surfaces as `{"ok": false, "code": "E_*", "detail": "..."}`:

`E_ARGS` bad parameters · `E_CONFIG` missing profiles/binary ·
`E_DAEMON` client process died · `E_CONN` / `E_CONN_TARGET` connect
failure · `E_AUTH` credentials rejected · `E_TIMEOUT` operation timeout ·
`E_SESSION_KICKED` another session displaced ours · `E_SERVER_HUNG` server
stopped responding · `E_BLACK` / `E_NOFRAME` no usable frame yet ·
`E_CAPABILITY` feature disabled in profile · `E_APP_START` RemoteApp
refused by guest policy · `E_ONESHOT_TERRITORY` daemon-only feature on a
oneshot target · `E_STATE` unexpected session state · `E_UNKNOWN`.

## 8. Troubleshooting

- **First screenshot is black** — wait ~1 s and re-shoot; resolution
  changes and fresh sessions legitimately need a frame or two.
- **`E_CONFIG: profiles file missing`** — create `gateway/profiles.json`
  from the sample; the repo never ships one.
- **Share `\\tsclient\<share>` empty right after push** — the redirect
  cache lags briefly; retry `dir` once after 1–2 s.
- **`E_APP_START`** — the guest's RemoteApp policy refuses the program;
  add it to the allow-list or set `fAllowUnlistedRemotePrograms`.
- **Session drops every N minutes** — another connection is competing for
  a single-session server; dedicate an account or enable multiple sessions.
- **Build failure on Windows GNU toolchains about dlltool/as** — install a
  complete MinGW binutils (e.g. MSYS2) or build with the MSVC target; the
  CI workflow on windows-latest is the reference environment.

## 9. CI artifacts

The [`build-rdputil`](.github/workflows/build-rdputil.yml) workflow builds
the client on every push/PR touching `tools/rdputil/**` and uploads
`rdputil-windows-x64` as an artifact; published releases get the binary
attached automatically. Download, `chmod`/unblock as needed, point
`GATEWAY_RDPUTIL` at it, and skip the local Rust toolchain entirely.
