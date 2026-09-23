import math,struct,tempfile,unittest,wave
from pathlib import Path
from omni.audio import analyze_speech_evidence, analyze_wav, word_error_rate
from omni.proof import merkle_root

class ProofAndAudioTests(unittest.TestCase):
    def test_merkle(self):
        with tempfile.TemporaryDirectory() as td:
            a=Path(td)/"a"; b=Path(td)/"b"; a.write_bytes(b"alpha"); b.write_bytes(b"beta")
            r1=merkle_root([b,a])["root"]; self.assertEqual(r1,merkle_root([a,b])["root"])
            b.write_bytes(b"gamma"); self.assertNotEqual(r1,merkle_root([a,b])["root"])

    def test_audio_gate(self):
        with tempfile.TemporaryDirectory() as td:
            good=str(Path(td)/"good.wav"); bad=str(Path(td)/"bad.wav"); rate=24000
            samples=[int(9000*math.sin(2*math.pi*440*i/rate)) for i in range(rate//4)]
            with wave.open(good,"wb") as w:
                w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
                w.writeframes(struct.pack("<"+"h"*len(samples),*samples))
            with wave.open(bad,"wb") as w:
                w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate); w.writeframes(b"\0\0"*len(samples))
            tone = analyze_wav(good)
            self.assertEqual(tone["status"],"PASS")
            self.assertEqual(tone["scope"],"SIGNAL_INTEGRITY_ONLY")
            self.assertFalse(tone["speech_verified"])
            self.assertEqual(analyze_wav(bad)["status"],"FAIL")

            speech = analyze_speech_evidence(
                good,
                reference_text="Secure Boot désactivé",
                recognized_text="secure boot désactivé",
                recognizer="independent-asr-test",
            )
            self.assertEqual(speech["status"],"PASS")
            self.assertTrue(speech["speech_verified"])
            self.assertEqual(speech["word_error_rate"],0.0)

            beep_not_speech = analyze_speech_evidence(
                good,
                reference_text="Secure Boot désactivé",
                recognized_text="bip",
                recognizer="independent-asr-test",
            )
            self.assertEqual(beep_not_speech["status"],"FAIL")
            self.assertIn("WORD_ERROR_RATE_EXCEEDED",beep_not_speech["failures"])

            missing_recognizer = analyze_speech_evidence(
                good,
                reference_text="Secure Boot désactivé",
                recognized_text="Secure Boot désactivé",
                recognizer="",
            )
            self.assertEqual(missing_recognizer["status"],"FAIL")
            self.assertIn("MISSING_RECOGNIZER_ID",missing_recognizer["failures"])

    def test_word_error_rate(self):
        self.assertEqual(word_error_rate("Bonjour le monde","bonjour le monde"),0.0)
        self.assertAlmostEqual(
            word_error_rate("un deux trois quatre","un deux quatre"),
            0.25,
        )
