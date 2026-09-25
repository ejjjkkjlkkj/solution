import unittest

from omni.voice_release import VOICE_REQUIRED_GATES, evaluate_voice_release


class VoiceReleaseTests(unittest.TestCase):
    def test_empty_manifest_cannot_pass(self):
        result = evaluate_voice_release({})
        self.assertEqual(result["status"], "VOICE_RELEASE_INCOMPLETE")
        self.assertEqual(result["missing"], sorted(VOICE_REQUIRED_GATES))

    def test_software_only_is_not_release_ready(self):
        software = {
            name: "PASS"
            for name in VOICE_REQUIRED_GATES
            if name not in {
                "french_intelligibility",
                "french_naturalness",
                "firmware_terms_intelligibility",
                "qemu_ovmf_pcm_path",
                "vmware_uefi_audio_path",
                "physical_hda_audio",
                "physical_speaker_intelligibility",
            }
        }
        result = evaluate_voice_release(software)
        self.assertEqual(result["status"], "VOICE_RELEASE_INCOMPLETE")
        self.assertIn("french_intelligibility", result["missing"])
        self.assertIn("physical_hda_audio", result["missing"])

    def test_not_run_is_a_blocker(self):
        manifest = {name: "PASS" for name in VOICE_REQUIRED_GATES}
        manifest["french_naturalness"] = "NOT_RUN"
        result = evaluate_voice_release(manifest)
        self.assertEqual(result["status"], "VOICE_RELEASE_INCOMPLETE")
        self.assertEqual(result["failed"], ["french_naturalness"])

    def test_unexpected_gate_is_a_blocker(self):
        manifest = {name: "PASS" for name in VOICE_REQUIRED_GATES}
        manifest["robotic_voice_override"] = "PASS"
        result = evaluate_voice_release(manifest)
        self.assertEqual(result["status"], "VOICE_RELEASE_INCOMPLETE")
        self.assertEqual(result["unexpected"], ["robotic_voice_override"])

    def test_exact_complete_manifest_passes(self):
        manifest = {name: "PASS" for name in VOICE_REQUIRED_GATES}
        result = evaluate_voice_release(manifest)
        self.assertEqual(result["status"], "VOICE_RELEASE_PASS")
        self.assertEqual(result["blockers"], [])


if __name__ == "__main__":
    unittest.main()
