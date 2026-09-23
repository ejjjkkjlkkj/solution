import unittest

from tools.verify_toolchain_lock import verify


class ToolchainLockTests(unittest.TestCase):
    def test_every_external_verification_input_is_pinned(self):
        result=verify()
        self.assertEqual(result["status"],"PASS",result["missing"])


if __name__=="__main__":
    unittest.main()
