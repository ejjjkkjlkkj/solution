import hashlib
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


class SigningFakeTpm(FakeTpm):
    """Ajoute CreatePrimary / Quote / FlushContext avec une vraie signature ECDSA P-256."""

    D = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF

    def __init__(self, fail_quote=False):
        super().__init__()
        self.flushed, self.fail_quote = [], fail_quote
        self.pub = t._mul(self.D, t._G)

    def __call__(self, cmd):
        tag, _size, code = struct.unpack_from(">HII", cmd, 0)
        if code == t.TPM_CC_CREATE_PRIMARY:
            x, y = (v.to_bytes(32, "big") for v in self.pub)
            pub = (struct.pack(">HHI", t.TPM_ALG_ECC, t.TPM_ALG_SHA256, 0x50072) + struct.pack(">H", 0)
                   + struct.pack(">HHHHH", t.TPM_ALG_NULL, t.TPM_ALG_ECDSA, t.TPM_ALG_SHA256, 3, t.TPM_ALG_NULL)
                   + t._b2(x) + t._b2(y))
            params = t._b2(pub) + t._b2(b"") * 3
            return struct.pack(">HII", 0x8002, 10 + 8 + len(params) + 5, 0) + struct.pack(">II", 0x80000000, len(params)) + params + b"\x00\x00\x00\x00\x00"
        if code == t.TPM_CC_FLUSH_CONTEXT:
            self.flushed.append(struct.unpack_from(">I", cmd, 10)[0])
            return _resp(b"")
        if code == t.TPM_CC_QUOTE:
            if self.fail_quote:
                return _resp(b"", rc=0x98E)
            # en-tete de la commande : tag size code handle authSize auth(9) nonce...
            pos = 10 + 4 + 4 + 9
            (n,) = struct.unpack_from(">H", cmd, pos)
            nonce = cmd[pos + 2:pos + 2 + n]
            pos += 2 + n + 4  # schema
            _count, _alg, sz = struct.unpack_from(">IHB", cmd, pos)
            bits = cmd[pos + 7:pos + 7 + sz]
            idx = [b * 8 + k for b in range(sz) for k in range(8) if bits[b] >> k & 1]
            digest = hashlib.sha256(b"".join(bytes([i]) * 32 for i in idx)).digest()
            attest = (struct.pack(">IH", t.TPM_GENERATED_VALUE, t.TPM_ST_ATTEST_QUOTE) + t._b2(b"\x00" * 34)
                      + t._b2(nonce) + struct.pack(">QIIBQ", 1, 0, 0, 1, 7)
                      + struct.pack(">IHB", 1, t.TPM_ALG_SHA256, sz) + bits + t._b2(digest))
            z = int.from_bytes(hashlib.sha256(attest).digest(), "big")
            k = 0x1111111111111111111111111111111111111111111111111111111111111111
            r = t._mul(k, t._G)[0] % t._N
            s = pow(k, -1, t._N) * (z + r * self.D) % t._N
            params = t._b2(attest) + struct.pack(">HH", t.TPM_ALG_ECDSA, t.TPM_ALG_SHA256) + t._b2(r.to_bytes(32, "big")) + t._b2(s.to_bytes(32, "big"))
            return struct.pack(">HII", 0x8002, 10 + 4 + len(params) + 5, 0) + struct.pack(">I", len(params)) + params + b"\x00\x00\x00\x00\x00"
        return super().__call__(cmd)


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

    def test_quote_roundtrip_and_tamper_detection(self):
        tpm = SigningFakeTpm()
        q = t.make_quote(tpm, (0, 1, 2))
        self.assertTrue(q["verification"]["valid"], q["verification"])
        self.assertEqual(tpm.flushed, [0x80000000])
        self.assertTrue(q["key_flushed"])
        pub = (int(q["public_key"]["x"], 16), int(q["public_key"]["y"], 16))
        raw = {"attest": bytes.fromhex(q["attest"]), "r": int(q["signature"]["r"], 16), "s": int(q["signature"]["s"], 16)}
        pcrs = t.read_pcrs(tpm, (0, 1, 2))
        nonce = bytes.fromhex(q["nonce"])
        self.assertTrue(t.verify_quote(raw, pub, nonce, pcrs)["valid"])
        self.assertFalse(t.verify_quote(raw, pub, b"x" * 32, pcrs)["nonce_match"])
        self.assertFalse(t.verify_quote({**raw, "s": raw["s"] ^ 1}, pub, nonce, pcrs)["signature_valid"])
        bad = {**pcrs, 0: "ff" * 32}
        self.assertFalse(t.verify_quote(raw, pub, nonce, bad)["pcr_digest_match"])

    def test_key_is_flushed_when_quote_fails(self):
        tpm = SigningFakeTpm(fail_quote=True)
        with self.assertRaises(t.TpmError):
            t.make_quote(tpm, (0,))
        self.assertEqual(tpm.flushed, [0x80000000])

    def test_speakable_tpm(self):
        out = speakable.render_tpm({"manufacturer": "AMD", "firmware_version": "1", "pcrs": {"0": "ab" * 32},
                                    "pcr_composite": "cd" * 32})
        self.assertTrue(out.startswith("Lecture du TPM reussie."))
        self.assertIn("aucun quote", out)
        self.assertTrue(out.endswith("Fin du rapport.\n"))


if __name__ == "__main__":
    unittest.main()
