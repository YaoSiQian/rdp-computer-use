"""Unit tests for gateway.rdp_file import mapping and pool wiring."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gateway import pool  # noqa: E402
from gateway.rdp_file import parse_rdp_file, rdp_to_profile  # noqa: E402

# A representative mstsc save: UTF-16LE, BOM, Windows-1252 era defaults plus
# the properties this gateway actually maps.
FULL_FILE = "\r\n".join(
    [
        "screen mode id:i:2",
        "desktopwidth:i:1600",
        "desktopheight:i:900",
        "session bpp:i:32",
        "compression:i:1",
        "keyboardhook:i:2",
        "audiomode:i:0",
        "redirectprinters:i:1",
        "redirectcomports:i:1",
        "redirectsmartcards:i:1",
        "redirectclipboard:i:0",
        "drivestoredirect:s:C:\\",
        "full address:s:rdp-target.example.net:4410",
        "server port:i:3391",
        "username:s:svc_operator",
        "domain:s:EXAMPLE",
        "redirectwebauthn:i:1",
    ]
) + "\r\n"


def write_rdp(text: str, encoding: str) -> Path:
    path = Path(tempfile.mkstemp(suffix=".rdp")[1])
    raw = text.encode(encoding)
    if encoding == "utf-16-le":
        raw = b"\xff\xfe" + raw
    path.write_bytes(raw)
    return path


class RdpFileTest(unittest.TestCase):
    def test_utf16_parse_and_map(self):
        prof = rdp_to_profile(write_rdp(FULL_FILE, "utf-16-le"))
        self.assertEqual(prof["host"], "rdp-target.example.net")
        self.assertEqual(prof["username"], "svc_operator")
        self.assertEqual(prof["domain"], "EXAMPLE")
        self.assertEqual(prof["desktop_size"], [1600, 900])
        self.assertFalse(prof["cliprdr"])
        self.assertTrue(prof["rdpdr"])

    def test_server_port_overrides_address_port(self):
        prof = rdp_to_profile(write_rdp(FULL_FILE, "utf-16-le"))
        self.assertEqual(prof["port"], 3391)
        self.assertTrue(any("3391" in n for n in prof["rdp_notes"]))

    def test_utf8_minimal(self):
        text = "full address:s:other.example.net\nusername:s:svc_backup\n"
        prof = rdp_to_profile(write_rdp(text, "utf-8"))
        self.assertEqual(prof["host"], "other.example.net")
        self.assertEqual(prof["username"], "svc_backup")
        self.assertNotIn("port", prof)
        self.assertNotIn("cliprdr", prof)
        self.assertNotIn("rdpdr", prof)

    def test_ipv6_bracket_address(self):
        text = "full address:s:[2001:db8::10]:3390\n"
        prof = rdp_to_profile(write_rdp(text, "utf-8"))
        self.assertEqual(prof["host"], "2001:db8::10")
        self.assertEqual(prof["port"], 3390)

    def test_noop_keys_are_reported(self):
        prof = rdp_to_profile(write_rdp(FULL_FILE, "utf-16-le"))
        joined = "\n".join(prof["rdp_notes"])
        self.assertIn("redirectprinters", joined)
        self.assertIn("audiomode", joined)
        self.assertIn("compression", joined)

    def test_reject_gateway_blob_and_entra(self):
        for fragment, marker in [
            ("password 51:b:5100000100000001\n", "DPAPI"),
            ("gatewayhostname:s:gw.example.net\n", "gateway"),
            ("kdcproxyname:s:kdc.example.net\n", "KDC"),
            ("enablerdsaadauth:i:1\n", "Entra"),
            ("targetisaadjoined:i:1\n", "Entra"),
        ]:
            with self.assertRaises(RuntimeError) as ctx:
                rdp_to_profile(write_rdp(fragment, "utf-8"))
            self.assertIn(marker, str(ctx.exception))

    def test_reject_flags_default_to_harmless(self):
        prof = rdp_to_profile(write_rdp("targetisaadjoined:i:0\nenablerdsaadauth:i:0\n", "utf-8"))
        self.assertNotIn("rdpdr", prof)


class PoolWiringTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.rdp = write_rdp(FULL_FILE, "utf-16-le")
        shutil.copy(self.rdp, Path(self.tmp) / self.rdp.name)
        self.env = {**os.environ}

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env)

    def _profiles(self, entry: dict) -> dict:
        path = Path(self.tmp) / "profiles.json"
        path.write_text(json.dumps({"profiles": entry}), encoding="utf-8")
        os.environ["GATEWAY_PROFILES"] = str(path)
        return pool.load_profiles()

    def test_file_is_base_json_is_overlay(self):
        profiles = self._profiles({"lab": {
            "rdp_file": self.rdp.name,
            "host": "overlay.example.net",
            "password_env": "GATEWAY_LAB_PASS",
        }})
        prof = profiles["lab"]
        self.assertEqual(prof["host"], "overlay.example.net")
        self.assertEqual(prof["username"], "svc_operator")
        self.assertEqual(prof["port"], 3391)
        self.assertEqual(prof["password_env"], "GATEWAY_LAB_PASS")
        self.assertEqual(prof["rdp_file"], str(Path(self.tmp) / self.rdp.name))

    def test_missing_file_fails_loud(self):
        with self.assertRaises(RuntimeError):
            self._profiles({"lab": {"rdp_file": "nope.rdp"}})


if __name__ == "__main__":
    unittest.main()
