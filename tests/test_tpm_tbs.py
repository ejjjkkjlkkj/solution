import struct
import unittest

from omni import speakable, tpm_tbs as t


def _resp(body: bytes, rc: int = 0) -> bytes:
    return struct.pack(">HII", 0x8001, 10 + len(body), rc) + body


class FakeTpm:
    """Repond aux trois commandes lues ; enregistre les commandes recues."""

    def __init__(self):
        self.seen = []

    def __call__(self, cmd: bytes) -> bytes:
        self.seen.append(cmd)
        tag, size, code = struct.unpack_from(">HII", cmd, 0)
        assert size == len(cmd) and tag == 0x8001
        if code == t.TPM_CC_GET_RANDOM:
            return _resp(struct.pack(">H", 4) + b"\x01\x02\x03\x04")
        if code == t.TPM_CC_GET_CAPABILITY:
            props = [(t.TPM_PT_MANUFACTURER, int.from_bytes(b"AMD\x00", "big")),
                     (t.TPM_PT_FIRMWARE_VERSION_1, 0x30057), (t.TPM_PT_FIRMWARE_VERSION_2, 5)]
            return _resp(b"\x00" + struct.pack(">II", 6, len(props)) + b"".join(struct.pack(">II", *p) for p in props))
        if code == t.TPM_CC_PCR_READ:
            _count, _alg, n = struct.unpack_from(">IHB", cmd, 10)
            bits = cmd[17:17 + n]
            idx = [b * 8 + k for b in range(n) for k in range(8) if bits[b] >> k & 1]
            body = struct.pack(">I", 7) + struct.pack(">IHB", 1, t.TPM_ALG_SHA256, n) + bits
            body += struct.pack(">I", len(idx)) + b"".join(struct.pack(">H", 32) + bytes([i]) * 32 for i in idx)
            return _resp(body)
        return _resp(b"", rc=0x143)


class TpmTests(unittest.TestCase):
    def test_get_random(self):
        self.assertEqual(t.get_random(FakeTpm(), 4), b"\x01\x02\x03\x04")
        with self.assertRaises(ValueError):
            t.get_random(FakeTpm(), 0)

    def test_identity(self):
        self.assertEqual(t.identity(FakeTpm()), {"manufacturer": "AMD", "firmware_version": "00030057.00000005"})

    def test_read_pcrs_and_composite(self):
        pcrs = t.read_pcrs(FakeTpm(), (0, 2, 7))
        self.assertEqual(sorted(pcrs), [0, 2, 7])
        self.assertEqual(pcrs[2], "02" * 32)
        self.assertEqual(len(t.pcr_composite(pcrs)), 64)

    def test_only_read_commands_are_sent(self):
        tpm = FakeTpm()
        t.identity(tpm), t.get_random(tpm), t.read_pcrs(tpm)
        codes = {struct.unpack_from(">I", c, 6)[0] for c in tpm.seen}
        self.assertEqual(codes, {t.TPM_CC_GET_CAPABILITY, t.TPM_CC_GET_RANDOM, t.TPM_CC_PCR_READ})

    def test_tpm_error_code_raises(self):
        with self.assertRaises(t.TpmError):
            t.get_random(lambda _c: _resp(b"", rc=0x921))

    def test_truncated_and_mismatched_responses_raise(self):
        with self.assertRaises(t.TpmError):
            t.get_random(lambda _c: b"\x80\x01")
        with self.assertRaises(t.TpmError):
            t.get_random(lambda _c: _resp(struct.pack(">H", 9) + b"\x01"))
        bad = bytearray(_resp(struct.pack(">H", 1) + b"\x01"))
        bad[5] += 1
        with self.assertRaises(t.TpmError):
            t.get_random(lambda _c: bytes(bad))

    def test_pcr_index_validation(self):
        for bad in ((), (1, 1), (24,), tuple(range(9))):
            with self.assertRaises(ValueError):
                t.read_pcrs(FakeTpm(), bad)

    def test_speakable_tpm(self):
        out = speakable.render_tpm({"manufacturer": "AMD", "firmware_version": "1", "pcrs": {"0": "ab" * 32},
                                    "pcr_composite": "cd" * 32})
        self.assertTrue(out.startswith("Lecture du TPM reussie."))
        self.assertIn("aucun quote", out)
        self.assertTrue(out.endswith("Fin du rapport.\n"))


if __name__ == "__main__":
    unittest.main()
