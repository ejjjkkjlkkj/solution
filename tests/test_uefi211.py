import unittest

from omni.uefi211 import (
    CATEGORY_ORDER,
    Coverage,
    ProtocolHit,
    UEFI_211_PROTOCOLS,
    analyze,
    analyze_file,
)


class Uefi211ProtocolTests(unittest.TestCase):
    def test_empty_blob_has_no_coverage(self):
        cov = analyze(b"")
        self.assertEqual(cov.bytes_total, 0)
        self.assertEqual(cov.hits, ())
        self.assertFalse(cov.passed())
        # Le mapping par categorie reste structure meme vide (6 categories vides).
        self.assertEqual(
            sum(len(v) for v in cov.by_category.values()),
            0,
        )
        self.assertEqual(cov.uefi_version, "unknown")

    def test_ascii_signatures_are_detected(self):
        blob = b"".join([
            b"\x00" * 100,
            b"EFI_HII_PACKAGE_LIST_PROTOCOL",
            b"\x00" * 50,
            b"EFI_VIRTUAL_KEYBOARD_PROTOCOL",
            b"\x00" * 50,
            b"HdaCodec",
        ])
        cov = analyze(blob)
        keys = {hit.key for hit in cov.hits}
        self.assertIn("hii_package_list", keys)
        self.assertIn("virtual_keyboard", keys)
        self.assertIn("hda_codec", keys)

    def test_utf16le_signatures_are_detected(self):
        blob = b"\x00" * 100 + "EFI_VIRTUAL_KEYBOARD_PROTOCOL".encode("utf-16-le")
        cov = analyze(blob)
        self.assertTrue(any(h.key == "virtual_keyboard" for h in cov.hits))

    def test_categories_are_partitioned(self):
        blob = b"".join([
            b"EFI_HII_PACKAGE_LIST_PROTOCOL",
            b"EFI_VIRTUAL_KEYBOARD_PROTOCOL",
            b"EFI_HTTP_PROTOCOL",
            b"EFI_TCP_PROTOCOL",
            b"HdaCodec",
            b"BeepProtocol",
            b"wireguard",
            b"suricata",
            b"Sysmon.exe",
        ])
        cov = analyze(blob)
        self.assertIn("hii", cov.by_category)
        self.assertIn("input", cov.by_category)
        self.assertIn("audio", cov.by_category)
        self.assertIn("network", cov.by_category)
        self.assertIn("vpn", cov.by_category)
        self.assertIn("ids", cov.by_category)
        # Ordre canonique.
        self.assertEqual(tuple(cov.by_category.keys()), CATEGORY_ORDER)

    def test_passed_requires_required_categories(self):
        blob = b"".join([
            b"EFI_HII_PACKAGE_LIST_PROTOCOL",
            b"EFI_VIRTUAL_KEYBOARD_PROTOCOL",
            b"HdaCodec",
        ])
        cov = analyze(blob)
        self.assertTrue(cov.passed(("hii", "audio", "input")))
        # Sans reseau exige, on peut PASS meme si aucun protocole reseau n'est detecte.
        self.assertFalse(cov.passed(("hii", "audio", "input", "network")))

    def test_first_signature_wins(self):
        # Deux signatures pour hda_codec -- on garde l'offset minimal.
        first = b"HdaCodec"
        second = b"HdaControllerInit"
        blob = second + b"\x00" * 100 + first + b"\x00" * 100
        cov = analyze(blob)
        hit = next(h for h in cov.hits if h.key == "hda_codec")
        self.assertEqual(hit.offset, 0)
        self.assertEqual(hit.signature, "HdaControllerInit")

    def test_uefi_version_detection(self):
        blob = b"some bytes mentioning UEFI 2.10 specification with text"
        cov = analyze(blob)
        self.assertEqual(cov.uefi_version, "2.10")
        self.assertTrue(cov.uefi_version_supported)
        # 2.11 est aussi supportee.
        cov2 = analyze(b"prefix UEFI 2.11 trail")
        self.assertEqual(cov2.uefi_version, "2.11")
        self.assertTrue(cov2.uefi_version_supported)

    def test_unknown_version_blocks_passed(self):
        # Si on declare explicitement une version < 2.10, on bloque le PASS.
        cov = analyze(b"prefix UEFI 2.9 trail")
        self.assertEqual(cov.uefi_version, "2.9")
        self.assertFalse(cov.uefi_version_supported)
        # La couverture HII/audio/input peut etre presente, mais passed() echoue.
        blob = b"EFI_HII_PACKAGE_LIST_PROTOCOL EFI_VIRTUAL_KEYBOARD_PROTOCOL HdaCodec UEFI 2.9"
        cov2 = analyze(blob)
        self.assertFalse(cov2.passed(("hii", "audio", "input")))

    def test_as_dict_is_json_serializable(self):
        import json
        blob = b"EFI_HII_PACKAGE_LIST_PROTOCOL"
        cov = analyze(blob)
        json.dumps(cov.as_dict())  # ne leve pas

    def test_analyze_file_round_trip(self, tmp_dir=None):
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        tmp.write(b"EFI_HII_PACKAGE_LIST_PROTOCOL"); tmp.close()
        try:
            cov = analyze_file(tmp.name)
            self.assertEqual(cov.bytes_total, len(b"EFI_HII_PACKAGE_LIST_PROTOCOL"))
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()