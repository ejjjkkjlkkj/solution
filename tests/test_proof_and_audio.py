import math,struct,tempfile,unittest,wave
from pathlib import Path
from omni.audio import analyze_wav
from omni.proof import merkle_root, verify_merkle

class ProofAndAudioTests(unittest.TestCase):
    def test_merkle_content_and_name_binding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a"
            b = root / "b"
            a.write_bytes(b"alpha")
            b.write_bytes(b"beta")
            manifest = merkle_root([b, a], base_dir=root)
            self.assertEqual(manifest["root"], merkle_root([a, b], base_dir=root)["root"])
            self.assertEqual(verify_merkle(manifest, base_dir=root)["status"], "PASS")

            original_root = manifest["root"]
            b.write_bytes(b"gamma")
            self.assertNotEqual(original_root, merkle_root([a, b], base_dir=root)["root"])
            failed = verify_merkle(manifest, base_dir=root)
            self.assertEqual(failed["status"], "FAIL")
            self.assertIn("ARTIFACT_1_DIGEST_MISMATCH", failed["errors"])

            b.write_bytes(b"beta")
            c = root / "c"
            b.rename(c)
            renamed = merkle_root([a, c], base_dir=root)
            self.assertNotEqual(original_root, renamed["root"])

    def test_merkle_rejects_path_traversal_and_bad_digest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "ok.bin"
            artifact.write_bytes(b"known")
            manifest = merkle_root([artifact], base_dir=root)

            traversed = dict(manifest)
            traversed["artifacts"] = [dict(manifest["artifacts"][0])]
            traversed["artifacts"][0]["path"] = "../ok.bin"
            result = verify_merkle(traversed, base_dir=root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("ARTIFACT_0_PATH_INVALID", result["errors"])

            malformed = dict(manifest)
            malformed["artifacts"] = [dict(manifest["artifacts"][0])]
            malformed["artifacts"][0]["sha256"] = "xyz"
            result = verify_merkle(malformed, base_dir=root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("ARTIFACT_0_DIGEST_INVALID", result["errors"])

    def test_merkle_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside_td:
            root = Path(td)
            outside = Path(outside_td) / "outside.bin"
            outside.write_bytes(b"secret")
            link = root / "link.bin"
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                merkle_root([link], base_dir=root)

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
