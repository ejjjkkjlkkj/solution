import tempfile, unittest
from pathlib import Path
from omni.semantic import SemanticModel
from omni.flight import build, verify
from omni.firmware import inspect
from omni.ceiling import REQUIRED_GATES, evaluate

class CoreTests(unittest.TestCase):
    def test_semantic_password_redaction(self):
        m = SemanticModel()
        m.apply({"sequence": 1, "kind": "node_created", "node": {"id": 1, "role": "edit", "name": "Password", "value": "secret", "state": ["password", "focusable"]}})
        self.assertFalse(m.passed)
        self.assertEqual(m.violations[0]["code"], "PASSWORD_VALUE_EXPOSED")

    def test_flight_detects_tamper(self):
        records = build([{"layer": "uefi", "type": "focus"}, {"layer": "mm", "type": "ping"}])
        self.assertTrue(verify(records)[0])
        records[1]["event"]["type"] = "tampered"
        self.assertFalse(verify(records)[0])

    def test_firmware_read_only_probe(self):
        blob = bytearray(256)
        base = 32
        blob[base + 40:base + 44] = b"_FVH"
        blob[base + 32:base + 40] = (128).to_bytes(8, "little")
        blob[base + 48:base + 50] = (56).to_bytes(2, "little")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "fw.bin"; p.write_bytes(blob)
            result = inspect(p)
            self.assertEqual(result["mutation"], False)
            self.assertEqual(len(result["firmware_volumes"]), 1)
            self.assertTrue(result["firmware_volumes"][0]["valid_bounds"])

    def test_ceiling_is_strict(self):
        partial = {"core_semantics": "PASS", "native_verification": "PASS"}
        result = evaluate(partial)
        self.assertEqual(result["status"], "SOFTWARE_INCOMPLETE")
        self.assertTrue(result["missing"])

        complete = {gate: "PASS" for gate in REQUIRED_GATES}
        self.assertEqual(evaluate(complete)["status"], "SOFTWARE_CEILING_PASS")

        complete["uefi_sct_runtime_ovmf"] = "NOT_RUN"
        result = evaluate(complete)
        self.assertEqual(result["status"], "SOFTWARE_INCOMPLETE")
        self.assertIn("uefi_sct_runtime_ovmf", result["failed"])

if __name__ == "__main__": unittest.main()
