import re
import unittest
from unittest import mock

from omni import host_chain, speakable

_DECORATIVE = re.compile(r"[|─-╿▀-▟←-⇿☀-➿\U0001F300-\U0001FAFF{}\[\]]")

CHAIN = {
    "passed": False,
    "firmware": {"bytes_total": 643, "uefi_version": "unknown"},
    "stages": [
        {"stage": "uefi_firmware", "label": "Firmware UEFI charge", "status": "ABSENT", "matched": 0, "expected": 1, "keys": []},
        {"stage": "os_accessibility", "label": "Accessibilite OS", "status": "OK", "matched": 1, "expected": 1, "keys": ["nvda"]},
    ],
}
SCAN = {
    "platform": "win32",
    "categories": {"a11y": [
        {"key": "nvda", "label": "NVDA", "installed": True, "running": True},
        {"key": "orca", "label": "Orca", "installed": False, "running": None},
    ]},
}
INVENTORY = {
    "platform_supported": True, "firmware_mode": "uefi", "errors": [],
    "fields": {"system_manufacturer": "ASUS", "baseboard_product": "M1603QA", "cpu": "Ryzen",
               "secure_boot_enabled": False, "hda_devices": [{"description": "Realtek"}], "keyboards": [{}]},
    "tpm": {"present": True, "version": "2.0"},
}


class SpeakableTests(unittest.TestCase):
    def check_shape(self, text: str) -> None:
        lines = text.splitlines()
        self.assertEqual(lines[-1], "Fin du rapport.")
        self.assertFalse(_DECORATIVE.search(text), text)
        self.assertTrue(all(line.strip() == line and line for line in lines))
        self.assertNotIn("\x1b", text)

    def test_verdict_is_first_line(self):
        out = speakable.render_chain(CHAIN)
        self.check_shape(out)
        self.assertTrue(out.startswith("Chaine incomplete : 1 etapes reussies sur 2."))
        self.assertIn("Etape 1 sur 2, Firmware UEFI charge : absent", out)

    def test_host_scan_states(self):
        out = speakable.render_host_scan(SCAN, True)
        self.check_shape(out)
        self.assertIn("NVDA : installe, en cours d'execution.", out)
        self.assertNotIn("Orca :", out)

    def test_inventory_and_identity(self):
        out = speakable.render_inventory(INVENTORY, {"status": "FAIL", "mismatches": ["cpu: missing"]})
        self.check_shape(out)
        self.assertTrue(out.startswith("Identite de la machine non conforme."))
        self.assertIn("Ecart : cpu: missing.", out)
        self.assertIn("Secure Boot : desactive.", out)
        self.assertIn("n'atteste aucun gate materiel", out)

    def test_unsupported_platform(self):
        self.check_shape(speakable.render_inventory({"platform_supported": False}))


class RunningStateTests(unittest.TestCase):
    def test_any_true_wins_even_after_a_false(self):
        with mock.patch.object(host_chain, "_service_running_win", side_effect=[False, True]), \
             mock.patch.object(host_chain, "_process_running", return_value=False):
            self.assertIs(host_chain._is_running(("a", "b")), True)

    def test_false_only_when_a_probe_answered_no(self):
        with mock.patch.object(host_chain, "_service_running_win", return_value=None), \
             mock.patch.object(host_chain, "_process_running", return_value=False):
            self.assertIs(host_chain._is_running(("a",)), False)

    def test_unknown_when_no_probe_concludes(self):
        with mock.patch.object(host_chain, "_service_running_win", return_value=None), \
             mock.patch.object(host_chain, "_process_running", return_value=None):
            self.assertIsNone(host_chain._is_running(("a",)))
        self.assertIsNone(host_chain._is_running(()))


if __name__ == "__main__":
    unittest.main()
