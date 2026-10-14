"""Import .rdp connection files as gateway profiles.

An .rdp file (mstsc "Save As", Azure Virtual Desktop portal downloads,
hand-edited) describes the same connection facts a profiles.json entry does,
so an entry may name one via `"rdp_file": "path/to/conn.rdp"` and skip
repeating host/port/username. The file is the connection-capability base;
keys written in the profile entry itself form the orchestration overlay and
win on conflict. Passwords never come from the file: they keep resolving
from the profile's `password_env`.

Parse rules follow the format mstsc writes: `key:type:value` lines with
case-insensitive keys and types `i` (32-bit int), `s` (string) and `b`
(binary hex). Windows mstsc saves UTF-16LE with a BOM while portal copies
are UTF-8, so the loader sniffs the BOM per file. Unknown keys are tolerated
and reported, never fatal.

Not every documented RDP property maps onto something this gateway can
honor. Recognized keys either map to gateway-native fields, are accepted
no-ops (the daemon simply never announces those channels or features), or
are rejected outright when honoring the file would require auth or transport
machinery (DPAPI blobs, RD Gateway, KDC proxy, Entra ID) that does not exist
on this side of the wire.
"""

from __future__ import annotations

import re
from pathlib import Path

# key -> reason; presence alone makes the file unusable here.
_REJECT_KEYS = {
    "gatewayhostname": "RD Gateway transport is not supported",
    "kdcproxyname": "KDC proxy authentication is not supported",
}

# key -> reason; rejected only when the file explicitly turns them on (=1).
_REJECT_FLAGS = {
    "enablerdsaadauth": "Entra ID (Azure AD) authentication is not supported",
    "targetisaadjoined": "targets joined to Entra ID (Azure AD) are not supported",
}

# Keys the gateway deliberately ignores, with the reason shown to the user.
# Redirect flags like printers/smart cards/com ports are defaults in most
# mstsc files and harmless: the daemon never announces those channels.
_NOOP_NOTES = {
    "compression": "serve mode has no compression toggle; transport-level compression is always negotiated by the engine",
    "autoreconnection enabled": "the daemon always reconnects dropped sessions",
    "audiomode": "audio output is not rendered",
    "videoplaybackmode": "video playback optimization is not implemented",
    "desktopscalefactor": "deprecated by Microsoft; DPI handling follows the engine",
    "promptcredentialonce": "credential prompts never reach the user; passwords come from the environment",
    "disableconnectionsharing": "connection sharing does not apply to a dedicated client",
    "alternate shell": "RemoteApp is a runtime operation (start_app tool), not a connect-time property",
    "shell working directory": "RemoteApp is a runtime operation (start_app tool), not a connect-time property",
}

# Everything documented but unmapped lands here with a generic reason.
_NOOP_DEFAULT = "not implemented by the gateway; the daemon ignores this property"

_LINE = re.compile(r"([^:]+):([isb]):(.*)")


def _decode(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig", errors="replace")


def parse_rdp_file(path: str | Path) -> dict[str, tuple[str, str]]:
    """Parse an .rdp file into {lowercased key: (type, value)}."""
    entries: dict[str, tuple[str, str]] = {}
    for line in _decode(Path(path).read_bytes()).splitlines():
        m = _LINE.fullmatch(line.strip())
        if m:
            entries[m.group(1).strip().lower()] = (m.group(2), m.group(3).strip())
    return entries


def rdp_to_profile(path: str | Path) -> dict:
    """Map a parsed .rdp file onto gateway-native profile keys.

    Returns a dict holding at most host, port, username, domain,
    desktop_size, cliprdr, rdpdr plus provenance/report lists. Raises
    RuntimeError when the file demands unsupported machinery.
    """
    entries = parse_rdp_file(path)
    source = str(path)
    notes: list[str] = []
    ignored: list[str] = []
    prof: dict = {"rdp_file": source, "rdp_notes": notes}

    for key, (typ, value) in entries.items():
        if key in _REJECT_KEYS:
            raise RuntimeError(f"{source}: key '{key}' is not usable here: {_REJECT_KEYS[key]}")
        if key in _REJECT_FLAGS and typ == "i" and value == "1":
            raise RuntimeError(f"{source}: key '{key}' is not usable here: {_REJECT_FLAGS[key]}")
        if typ == "b" and key.split()[0] == "password":
            raise RuntimeError(
                f"{source}: '{key}:b' holds a DPAPI blob bound to the machine that saved the file; "
                "set password_env instead"
            )

    address = entries.get("full address", ("s", ""))[1]
    host, addr_port = _split_address(address)
    if host:
        prof["host"] = host
    if addr_port is not None:
        prof["port"] = addr_port

    if "server port" in entries:
        try:
            port = int(entries["server port"][1])
        except ValueError:
            raise RuntimeError(f"{source}: 'server port' is not an integer: {entries['server port'][1]!r}") from None
        if "port" in prof and prof["port"] != port:
            notes.append(f"server port {port} (from 'server port') overrides the port in 'full address'")
        prof["port"] = port

    username = entries.get("username", ("s", ""))[1]
    if username:
        prof["username"] = username
    domain = entries.get("domain", ("s", ""))[1]
    if domain:
        prof["domain"] = domain
    if "password" in entries:
        ignored.append("password (plaintext passwords from files are not used; password_env resolves the secret)")

    try:
        width = int(entries["desktopwidth"][1])
        height = int(entries["desktopheight"][1])
    except (KeyError, ValueError):
        pass
    else:
        if width > 0 and height > 0:
            prof["desktop_size"] = [width, height]

    if entries.get("redirectclipboard") == ("i", "0"):
        prof["cliprdr"] = False
        notes.append("clipboard redirection disabled by 'redirectclipboard:i:0'")

    drives = entries.get("drivestoredirect", ("s", ""))[1]
    if drives:
        prof["rdpdr"] = True
        notes.append(
            "drive redirection enabled by 'drivestoredirect'; the gateway redirects its own dedicated root, "
            "not the drives the file lists"
        )

    for key in entries:
        if key in ("full address", "server port", "username", "domain", "desktopwidth", "desktopheight",
                   "redirectclipboard", "drivestoredirect") \
                or key.split()[0] == "password" or key in _REJECT_KEYS or key in _REJECT_FLAGS:
            continue
        ignored.append(f"{key} ({_NOOP_NOTES.get(key, _NOOP_DEFAULT)})")

    notes.extend(f"ignored: {item}" for item in ignored)
    return prof


def _split_address(address: str) -> tuple[str, int | None]:
    """Split 'host:port' / '[v6]:port'; bare IPv6 stays a single host."""
    if address.startswith("["):
        host, _, rest = address.partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host[1:], int(rest[1:])
        return address, None
    if address.count(":") == 1:
        host, _, port = address.partition(":")
        if port.isdigit():
            return host, int(port)
    return address, None
