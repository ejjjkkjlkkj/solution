import math,struct,tempfile,unittest,wave
from pathlib import Path
from omni.audio import analyze_wav
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
            self.assertEqual(analyze_wav(good)["status"],"PASS")
            self.assertEqual(analyze_wav(bad)["status"],"FAIL")
