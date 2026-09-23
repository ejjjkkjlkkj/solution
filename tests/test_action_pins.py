import unittest

from tools.verify_action_pins import verify


class ActionPinTests(unittest.TestCase):
    def test_all_external_actions_are_immutable_sha_pinned(self):
        result = verify()
        self.assertEqual(result["status"], "PASS", result["violations"])
        self.assertGreater(result["checked"], 0)


if __name__ == "__main__":
    unittest.main()
