import math,struct,tempfile,unittest,wave
from pathlib import Path
from omni.audio import analyze_wav
from omni.proof import merkle_root, verify_merkle

class ProofAndAudioTests(unittest.TestCase):
    def test_merkle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a"
            b = root / "b"
            a.write_bytes(b"alpha")
            b.write_bytes(b"beta")

            manifest = merkle_root([b, a], base_dir=root)
            self.assertEqual(
                manifest["root"],
                merkle_root([a, b], base_dir=root)["root"],
            )
            self.assertEqual(verify_merkle(manifest, base_dir=root)["status"], "PASS")

            original_root = manifest["root"]
            b.write_bytes(b"gamma")
            self.assertNotEqual(
                original_root,
                merkle_root([a, b], base_dir=root)["root"],
            )
            failed = verify_merkle(manifest, base_dir=root)
            self.assertEqual(failed["status"], "FAIL")
            self.assertIn("ARTIFACT_1_DIGEST_MISMATCH", failed["errors"])

    def test_merkle_binds_filename(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a"
            b = root / "b"
            c = root / "c"
            a.write_bytes(b"same")
            b.write_bytes(b"same")
            before = merkle_root([a, b], base_dir=root)["root"]
            b.rename(c)
            after = merkle_root([a, c], base_dir=root)["root"]
            self.assertNotEqual(before, after)

    def test_audio_gate(self):
        with tempfile.TemporaryDirectory() as td:
            good=str(Path(td)/"good.wav"); bad=str(Path(td)/"bad.wav"); rate=24000
            samples=[int(9000*math.sin(2*math.pi*440*i/rate)) for i in range(rate//4)]
            with wave.open(good,"wb") as w:
                w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
                w.writeframes(struct.pack("<"+"h"*len(samples),*samples))
            with wave.open(bad,"wb") as w:
                w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate); w.writeframes(b"\0\0"*len(samples))
            self.assertEqual(analyze_wav(good)["status"],"PASS")
            self.assertEqual(analyze_wav(bad)["status"],"FAIL")
