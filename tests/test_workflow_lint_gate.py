import unittest

from omni.ceiling import REQUIRED_GATES
from tools.ci_ceiling_manifest import WORKFLOW_TO_GATES


class WorkflowLintGateTests(unittest.TestCase):
    def test_workflow_lint_is_required(self):
        self.assertIn("ci_workflow_lint", REQUIRED_GATES)
        self.assertEqual(WORKFLOW_TO_GATES["CI Workflow Lint"], ("ci_workflow_lint",))


if __name__=="__main__":
    unittest.main()
