import unittest

from tools.ci_ceiling_manifest import WORKFLOW_TO_GATES, build


def run(name, sha="abc", status="completed", conclusion="success", number=1):
    return {
        "id": number,
        "name": name,
        "head_sha": sha,
        "event": "push",
        "status": status,
        "conclusion": conclusion,
        "run_number": number,
        "created_at": f"2026-01-01T00:00:{number:02d}Z",
        "html_url": "https://example.invalid/run",
    }


class CiCeilingManifestTests(unittest.TestCase):
    def test_all_required_workflows_success(self):
        payload = {"workflow_runs": [run(name) for name in WORKFLOW_TO_GATES]}
        manifest, details = build(payload, "abc")
        self.assertTrue(details["ready"])
        self.assertTrue(all(value == "PASS" for value in manifest.values()))

    def test_missing_workflow_is_not_ready(self):
        names = list(WORKFLOW_TO_GATES)[:-1]
        manifest, details = build({"workflow_runs": [run(name) for name in names]}, "abc")
        self.assertFalse(details["ready"])
        self.assertIn("MISSING", manifest.values())

    def test_in_progress_workflow_is_not_ready(self):
        payload = {"workflow_runs": [run(name) for name in WORKFLOW_TO_GATES]}
        payload["workflow_runs"][-1]["status"] = "in_progress"
        payload["workflow_runs"][-1]["conclusion"] = None
        manifest, details = build(payload, "abc")
        self.assertFalse(details["ready"])
        self.assertIn("NOT_RUN", manifest.values())

    def test_failed_completed_workflow_is_ready_but_not_pass(self):
        payload = {"workflow_runs": [run(name) for name in WORKFLOW_TO_GATES]}
        payload["workflow_runs"][-1]["conclusion"] = "failure"
        manifest, details = build(payload, "abc")
        self.assertTrue(details["ready"])
        self.assertIn("FAILURE", manifest.values())

    def test_latest_run_wins(self):
        payload = {"workflow_runs": []}
        for name in WORKFLOW_TO_GATES:
            payload["workflow_runs"].append(run(name, number=1))
        payload["workflow_runs"].append(run("UEFI SCT Build", conclusion="failure", number=2))
        manifest, details = build(payload, "abc")
        self.assertTrue(details["ready"])
        self.assertEqual(manifest["uefi_sct_build"], "FAILURE")


if __name__ == "__main__":
    unittest.main()
