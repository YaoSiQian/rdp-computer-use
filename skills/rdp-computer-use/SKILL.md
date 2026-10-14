---
name: rdp-computer-use
description: Drive a remote Windows desktop over RDP from an agent - observe with screenshots, act with mouse/keyboard, sync the clipboard, push and pull files, and run task-scoped RemoteApps through the rdp-computer-use MCP server. Use when a task requires seeing or operating a remote Windows machine, automating GUI applications there, or transferring files to and from it.
---

# Operating a remote desktop with rdp-computer-use

## How you are connected

An MCP server named `rdp-<profile>` exposes the remote desktop as tools.
It talks to a long-lived RDP session on the target machine; the session
already exists (or is created lazily on your first call). You never touch
the RDP protocol itself - every interaction goes through the tools below.

If no tool is reachable, the server is not running: the human starts it with
`python -m gateway --mcp --profile <name>` (from the rdp-computer-use
repository, with the profile's password environment variable set).

## The working loop

Always work screen-blind-safe: never act on stale screen state.

1. `screenshot` - observe. The result includes the image plus metadata
   (`native` vs `scaled` size, `mean_lum`, `distinct`, `stable`).
2. Decide the next action and its target coordinates.
3. Act: `click` / `move` / `type_text` / `key` / `scroll`.
4. `screenshot` again to confirm the effect before continuing.

Rules that keep the loop reliable:

- **Coordinates are in screenshot pixels.** If you took the image at the
  scaled size, pass scaled coordinates (default); pass `native: true` only
  when you mean full-resolution desktop coordinates. `screenshot` metadata
  tells you both sizes and the scale factor.
- **Wait for windows to exist before interacting.** After launching
  something (Enter on a Run dialog, a start-menu search, `start_app`),
  `wait` ~1500-2500 ms, then screenshot.
- **`key` takes combos** like `enter`, `alt+f4`, `win+r`, `ctrl+shift+esc`.
  For prose, use `type_text`, never `key`.
- **Empty or black screenshots** right after a resolution change are real:
  `wait` 1000 ms and re-shoot before concluding anything.

## Clipboard

The host (agent side) and guest clipboards stay in sync:

- `clipboard_set` puts text on the guest clipboard - then focus a text
  field in the guest and paste (`key: ctrl+v`).
- `clipboard_get` reads back what the guest copied. After triggering a
  guest-side copy, `wait` ~1500 ms before `clipboard_get`.

Use the clipboard for *text content*; use file transfer for anything that
must exist as a file on disk.

## File transfer

Requires the target to have drive redirection (`rdpdr: true` in the
profile). The gateway exposes a host directory to the guest as a network
share `\\tsclient\<share-name>` (share name from the profile; typically
`tools`).

- `file_push(local_path, guest_name)` - copy a host file into the guest.
  The file appears under `\\tsclient\<share>\...` on the guest; from a
  cmd window copy it where it is needed
  (`copy \\tsclient\tools\probe.txt C:\Users\...\probe.txt`).
- `file_pull(guest_path, local_path)` - copy a guest file back to the host.

Pushed files are read by the guest directly from the share; if a `dir`
immediately after push shows nothing, wait 1-2 s and retry once - the
redirect cache can lag briefly.

## RemoteApp (task-scoped applications)

`start_app("notepad.exe")` switches the session into RemoteApp mode: only
the launched application's window is presented, no desktop.

- This **tears down the current desktop session** on the target - state on
  screen is gone.
- The session **ends when the app exits**; that is normal. The next tool
  call automatically gets a fresh desktop session.
- The guest must allow the program as a RemoteApp (allow-list or the
  `fAllowUnlistedRemotePrograms` policy). If not, you get `E_APP_START`
  and the previous session mode is restored on the next call.
- Use RemoteApp when the whole task lives inside one application;
  use the desktop when the task spans apps or the shell.

## `state` and `resize`

- `state` returns session facts: connected time, desktop size, current
  app window id, input counters. Call it when behavior seems off.
- `resize(w, h)` changes the remote resolution (needs
  `display_control: true` in the profile). After resizing, wait ~1 s;
  the first screenshot can be blank. Restore the previous size when done.

## Error codes and recovery

| Code | Meaning | What to do |
| --- | --- | --- |
| `E_CONN` / `E_CONN_TARGET` | RDP connect failed | Check host/username in the profile; `probe` to test reachability |
| `E_AUTH` | Authentication failed | Credentials in the profile / password env var |
| `E_TIMEOUT` | Operation timed out | Retry once; check `state` |
| `E_SESSION_KICKED` | Another session took over | Reconnect by calling any tool |
| `E_SERVER_HUNG` | Server stopped responding | `close`, then any tool reconnects |
| `E_APP_START` | RemoteApp refused by guest | Guest policy; fall back to desktop mode |
| `E_BLACK` / `E_NOFRAME` | No usable frame yet | `wait` 1000 ms, screenshot again |
| `E_CAPABILITY` | Feature not enabled | Enable `rdpdr` / `display_control` in the profile |
| `E_DAEMON` | Client binary crashed | Restart the gateway process |

## Environment probe

`probe` runs a safe, slow detection pass (TCP reachability, protocol
handshake hints). Use it once when a target is new or failing - not in
the normal loop.
