import unittest

from omni import end_to_end, host_chain, uefi211


def _rich_firmware() -> bytes:
    """Firmware qui couvre HII, audio, input et network UEFI 2.10/2.11."""
    return b"".join([
        b"EFI_HII_PACKAGE_LIST_PROTOCOL",
        b"EFI_HII_FONT_PROTOCOL",
        b"EFI_VIRTUAL_KEYBOARD_PROTOCOL",
        b"EFI_USB_HID_PROTOCOL",
        b"HdaCodec",
        b"VoiceOutput",
        b"BeepProtocol",
        b"EFI_HTTP_PROTOCOL",
        b"EFI_TCP_PROTOCOL",
    ])


class EndToEndChainTests(unittest.TestCase):
    def test_full_chain_passes_when_everything_present(self):
        fw = _rich_firmware()
        cov = uefi211.analyze(fw)
        det = host_chain.scan_file_hints([
            r"C:\Program Files\NVDA",   # a11y
            "/usr/bin/wg",              # vpn
            "/usr/bin/suricata",        # ids
        ])
        host = host_chain.HostScan(platform="static", detections=tuple(det))
        report = end_to_end.build_chain(cov, host)
        self.assertTrue(report.passed())
        self.assertEqual(report.firmware_sha256, cov.sha256)
        self.assertEqual(report.host_platform, "static")
        self.assertEqual(report.uefi_version, cov.uefi_version)

    def test_chain_fails_without_a11y(self):
        # Pour ce test on construit un HostScan vide d'a11y (mais avec vpn+ids)
        # directement, pour ne pas dependre de l'etat reel de la machine.
        cov = uefi211.analyze(_rich_firmware())
        host = host_chain.HostScan(platform="static", detections=(
            host_chain.Detection(key="wireguard", label="WireGuard", category="vpn",
                                  installed=True, running=None, evidence="hint"),
            host_chain.Detection(key="suricata", label="Suricata", category="ids",
                                  installed=True, running=None, evidence="hint"),
        ))
        report = end_to_end.build_chain(cov, host)
        os_stage = report.stage("os_accessibility")
        self.assertIsNotNone(os_stage)
        self.assertEqual(os_stage.status, "ABSENT")
        self.assertFalse(report.passed())

    def test_chain_fails_without_uefi_audio(self):
        # Firmware sans HdaCodec ni VoiceOutput.
        fw = b"EFI_HII_PACKAGE_LIST_PROTOCOL EFI_VIRTUAL_KEYBOARD_PROTOCOL"
        cov = uefi211.analyze(fw)
        det = host_chain.scan_file_hints([r"C:\Program Files\NVDA"])
        host = host_chain.HostScan(platform="static", detections=tuple(det))
        report = end_to_end.build_chain(cov, host)
        audio_stage = report.stage("uefi_accessibility")
        self.assertIsNotNone(audio_stage)
        self.assertEqual(audio_stage.status, "PARTIEL")

    def test_stages_have_required_keys(self):
        fw = _rich_firmware()
        cov = uefi211.analyze(fw)
        det = host_chain.scan_file_hints([
            r"C:\Program Files\NVDA",
            "/usr/bin/wg",
            "/usr/bin/suricata",
        ])
        host = host_chain.HostScan(platform="static", detections=tuple(det))
        report = end_to_end.build_chain(cov, host)
        names = [s.stage for s in report.stages]
        self.assertEqual(
            names,
            ["uefi_firmware", "uefi_accessibility", "uefi_network",
             "os_accessibility", "network_security", "intrusion"],
        )

    def test_as_dict_is_json_serializable(self):
        import json
        fw = _rich_firmware()
        cov = uefi211.analyze(fw)
        det = host_chain.scan_file_hints([r"C:\Program Files\NVDA"])
        host = host_chain.HostScan(platform="static", detections=tuple(det))
        report = end_to_end.build_chain(cov, host)
        json.dumps(report.as_dict())  # ne leve pas


class ChainBuildVariantsTests(unittest.TestCase):
    def test_build_chain_from_bytes(self):
        det = host_chain.scan_file_hints([r"C:\Program Files\NVDA"])
        host = host_chain.HostScan(platform="static", detections=tuple(det))
        report = end_to_end.build_chain_from_bytes(_rich_firmware(), host)
        self.assertTrue(report.passed())

    def test_build_chain_from_paths_uses_static_hints(self):
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        tmp.write(_rich_firmware()); tmp.close()
        try:
            report = end_to_end.build_chain_from_paths(
                tmp.name,
                host_hints=[r"C:\Program Files\NVDA"],
                scan_live=False,
            )
            self.assertTrue(report.passed())
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()

class ActiveStateTests(unittest.TestCase):
    def _report(self, running):
        from omni import end_to_end, host_chain, uefi211
        det = host_chain.Detection(key="sysmon", label="Sysmon", category="ids",
                                   installed=True, running=running, evidence="x")
        host = host_chain.HostScan(platform="t", detections=(det,))
        return end_to_end.build_chain(uefi211.analyze(b""), host).stage("intrusion")

    def test_stopped_ids_does_not_count(self):
        self.assertEqual(self._report(False).status, "ABSENT")

    def test_running_or_unknown_ids_counts(self):
        self.assertEqual(self._report(True).status, "OK")
        self.assertEqual(self._report(None).status, "OK")
