import unittest

from omni.ceiling import REQUIRED_GATES
from tools.ci_ceiling_manifest import WORKFLOW_TO_GATES


class FormalSemanticGateTests(unittest.TestCase):
    def test_formal_semantic_proof_is_required(self):
        self.assertIn("formal_semantic_proof", REQUIRED_GATES)
        self.assertEqual(
            WORKFLOW_TO_GATES["Formal Semantic Proof"],
            ("formal_semantic_proof",),
        )


if __name__=="__main__":
    unittest.main()
