import tempfile
import unittest
from pathlib import Path

from tools.workflow_policy import inspect


class WorkflowPolicyTests(unittest.TestCase):
    def scan(self, text: str):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "ci.yml").write_text(text, encoding="utf-8")
            return inspect(root)

    def test_commit_pinned_action_passes(self):
        sha = "a" * 40
        self.assertEqual(self.scan(f"steps:\n  - uses: actions/checkout@{sha} # v4\n"), [])

    def test_moving_tag_is_rejected(self):
        violations = self.scan("steps:\n  - uses: actions/checkout@v4\n")
        self.assertEqual(violations[0].code, "ACTION_NOT_COMMIT_PINNED")

    def test_continue_on_error_true_is_rejected(self):
        violations = self.scan("jobs:\n  x:\n    continue-on-error: true\n")
        self.assertEqual(violations[0].code, "CONTINUE_ON_ERROR_TRUE")

    def test_local_action_is_allowed(self):
        self.assertEqual(self.scan("steps:\n  - uses: ./local-action\n"), [])

    def test_docker_requires_digest(self):
        violations = self.scan("steps:\n  - uses: docker://alpine:latest\n")
        self.assertEqual(violations[0].code, "DOCKER_NOT_DIGEST_PINNED")
        digest = "b" * 64
        self.assertEqual(self.scan(f"steps:\n  - uses: docker://alpine@sha256:{digest}\n"), [])


if __name__ == "__main__":
    unittest.main()
