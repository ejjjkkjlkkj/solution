import unittest

from omni.ceiling import CHAIN_GATE_KEYS, evaluate_chain


class CeilingChainGateTests(unittest.TestCase):
    def test_chain_gate_keys_are_distinct_from_software(self):
        # Les chain gates ne sont PAS dans REQUIRED_SOFTWARE_GATES (l'existant
        # reste intact). On verifie qu'ils sont bien declares comme un set
        # ferme et disjoint.
        from omni.ceiling import REQUIRED_SOFTWARE_GATES
        self.assertTrue(CHAIN_GATE_KEYS.isdisjoint(REQUIRED_SOFTWARE_GATES))

    def test_complete_pass_set(self):
        statuses = {k: "PASS" for k in CHAIN_GATE_KEYS}
        result = evaluate_chain(statuses)
        self.assertEqual(result["status"], "CHAIN_REPORT_PASS")
        self.assertEqual(result["failed"], [])
        self.assertEqual(result["missing"], [])

    def test_missing_gate_blocks_pass(self):
        statuses = {k: "PASS" for k in CHAIN_GATE_KEYS}
        statuses["host_ips"] = "FAIL"
        result = evaluate_chain(statuses)
        self.assertEqual(result["status"], "CHAIN_REPORT_INCOMPLETE")
        self.assertIn("host_ips", result["failed"])

    def test_unexpected_keys_are_reported(self):
        statuses = {k: "PASS" for k in CHAIN_GATE_KEYS}
        statuses["unexpected_gate"] = "PASS"
        result = evaluate_chain(statuses)
        self.assertEqual(result["status"], "CHAIN_REPORT_INCOMPLETE")
        self.assertIn("unexpected_gate", result["unexpected"])

    def test_invalid_status_is_blocker(self):
        statuses = {k: "PASS" for k in CHAIN_GATE_KEYS}
        statuses["host_a11y"] = "GARBAGE"
        result = evaluate_chain(statuses)
        self.assertEqual(result["status"], "CHAIN_REPORT_INCOMPLETE")
        self.assertIn("host_a11y", result["invalid"])

    def test_required_field_lists_all_chain_gates(self):
        statuses = {k: "PASS" for k in CHAIN_GATE_KEYS}
        result = evaluate_chain(statuses)
        self.assertEqual(set(result["required"]), set(CHAIN_GATE_KEYS))


if __name__ == "__main__":
    unittest.main()