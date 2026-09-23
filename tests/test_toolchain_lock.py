import unittest

from tools.verify_toolchain_lock import verify


class ToolchainLockTests(unittest.TestCase):
    def test_external_verification_inputs_match_lock(self):
        result = verify()
        self.assertEqual(result["status"], "PASS", result["missing"])
        self.assertGreater(len(result["checked_files"]), 0)


if __name__ == "__main__":
    unittest.main()
