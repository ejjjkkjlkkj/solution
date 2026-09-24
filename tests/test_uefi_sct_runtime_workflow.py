from __future__ import annotations

import pathlib
import unittest


WORKFLOW = pathlib.Path(".github/workflows/uefi-sct-runtime.yml")


class UefiSctRuntimeWorkflowTests(unittest.TestCase):
    def test_fresh_run_is_started_once_then_resumed(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        marker = "OMNI-FIR.STA"
        remove_marker = r"rm FS%i:\Sct\OMNI-FIR.STA"
        fresh = "Sct -r -a -f -v"
        resume = "Sct -c -f -v"

        self.assertIn(marker, text)
        self.assertIn(remove_marker, text)
        self.assertIn(fresh, text)
        self.assertIn(resume, text)
        self.assertLess(text.index(remove_marker), text.index(fresh))

    def test_runtime_requires_completion_and_real_sct_results(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("OMNI_SCT_RETURNED", text)
        self.assertIn("::/Sct/Overall", text)
        self.assertIn(
            'python tools/sct_summary.py "$SUMMARY_LOG" --json-out sct-summary.json --strict',
            text,
        )


if __name__ == "__main__":
    unittest.main()
