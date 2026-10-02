import struct
import unittest
import uuid

from omni import host_inventory as hi


def _table(major=3, minor=4) -> bytes:
    u = uuid.UUID("12345678-1234-5678-1234-567812345678")
    # Type 0 : vendor@4, version@5, release date@8 (octets formates 0-based incl. en-tete)
    bios = bytes([0, 0x12]) + b"\x00\x00" + bytes([1, 2]) + b"\x00\x00" + bytes([3]) + b"\x00" * 9
    bios += b"AMI\x00M1603QA.308\x00" + b"05/22/2023\x00\x00"
    sysinfo = bytes([1, 0x1B]) + b"\x00\x00" + bytes([1, 2, 0, 0]) + u.bytes_le + b"\x00" * 3
    sysinfo += b"ASUSTeK COMPUTER INC.\x00VivoBook\x00\x00"
    end = bytes([127, 4, 0, 0, 0, 0])
    tbl = bios + sysinfo + end
    return bytes([0, major, minor, 0]) + struct.pack("<I", len(tbl)) + tbl


class SmbiosTests(unittest.TestCase):
    def test_parses_bios_and_system(self):
        d = hi.parse_smbios(_table())
        self.assertEqual(d["smbios_version"], "3.4")
        self.assertEqual(d["bios_vendor"], "AMI")
        self.assertEqual(d["bios_version"], "M1603QA.308")
        self.assertEqual(d["system_manufacturer"], "ASUSTeK COMPUTER INC.")
        self.assertEqual(d["system_uuid"], "12345678-1234-5678-1234-567812345678")

    def test_nil_uuid_is_none(self):
        raw = bytearray(_table())
        i = raw.index(uuid.UUID("12345678-1234-5678-1234-567812345678").bytes_le)
        raw[i:i + 16] = b"\xff" * 16
        self.assertIsNone(hi.parse_smbios(bytes(raw))["system_uuid"])

    def test_truncated_table_raises(self):
        with self.assertRaises(ValueError):
            hi.parse_smbios(_table()[:-5])
        with self.assertRaises(ValueError):
            hi.parse_smbios(b"\x00")


class CollectTests(unittest.TestCase):
    def test_non_windows_is_unsupported(self):
        inv = hi.collect(platform="linux")
        self.assertFalse(inv.platform_supported)
        self.assertEqual(hi.check_identity(inv, hi.ASUS_M1603QA)["status"], "FAIL")

    def _inv(self, **over):
        reg = {"baseboard_product": "M1603QA", "cpu": "AMD Ryzen 7 5800H with Radeon Graphics",
               "secure_boot_enabled": False, "hda_devices": [], "keyboards": []}
        reg.update(over)
        return hi.collect(platform="win32", smbios_source=_table,
                          registry_source=lambda: reg, tpm_source=lambda: {"present": True, "version": "2.0"})

    def test_identity_pass(self):
        inv = self._inv()
        self.assertEqual(inv.firmware_mode, "uefi")
        self.assertEqual(hi.check_identity(inv, hi.ASUS_M1603QA)["status"], "PASS")

    def test_identity_mismatch_and_missing_fail_closed(self):
        self.assertEqual(hi.check_identity(self._inv(cpu="Intel i7"), hi.ASUS_M1603QA)["status"], "FAIL")
        r = hi.check_identity(self._inv(baseboard_product=None), hi.ASUS_M1603QA)
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("baseboard_product: missing", r["mismatches"])

    def test_uuid_expectation(self):
        inv = self._inv()
        ok = hi.IdentityExpectation(system_uuid="12345678-1234-5678-1234-567812345678")
        bad = hi.IdentityExpectation(system_uuid="87654321-1234-5678-1234-567812345678")
        self.assertEqual(hi.check_identity(inv, ok)["status"], "PASS")
        self.assertEqual(hi.check_identity(inv, bad)["status"], "FAIL")

    def test_never_attests_gates_and_hash_is_stable(self):
        a, b = self._inv().to_dict(), self._inv().to_dict()
        self.assertEqual(a["gates_attested"], [])
        self.assertEqual(a["inventory_sha256"], b["inventory_sha256"])

    def test_source_failures_are_reported(self):
        def boom():
            raise OSError("denied")
        inv = hi.collect(platform="win32", smbios_source=boom, registry_source=boom, tpm_source=boom)
        self.assertEqual(len(inv.errors), 3)
        self.assertEqual(inv.firmware_mode, "unknown")


if __name__ == "__main__":
    unittest.main()
