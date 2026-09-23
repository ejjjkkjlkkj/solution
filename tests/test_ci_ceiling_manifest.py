import unittest

from omni.ceiling import REQUIRED_GATES, evaluate
from tools.ci_ceiling_manifest import WORKFLOW_TO_GATES, build


class CiCeilingManifestTests(unittest.TestCase):
    SHA = "a" * 40

    def make_run(self, name, *, run_number, status="completed", conclusion="success", event="push"):
        return {
            "id": run_number,
            "name": name,
            "head_sha": self.SHA,
            "event": event,
            "run_number": run_number,
            "created_at": f"2026-09-23T13:{run_number % 60:02d}:00Z",
            "status": status,
            "conclusion": conclusion,
            "html_url": f"https://example.invalid/{run_number}",
        }

    def test_complete_success_set_passes_exact_policy(self):
        runs = [
            self.make_run(name, run_number=index + 1)
            for index, name in enumerate(WORKFLOW_TO_GATES)
        ]
        manifest, details = build({"workflow_runs": runs}, self.SHA)
        self.assertTrue(details["ready"])
        self.assertEqual(set(manifest), set(REQUIRED_GATES))
        self.assertEqual(evaluate(manifest)["status"], "SOFTWARE_CEILING_PASS")

    def test_missing_or_in_progress_is_not_ready(self):
        names = list(WORKFLOW_TO_GATES)
        runs = [
            self.make_run(name, run_number=index + 1)
            for index, name in enumerate(names[:-1])
        ]
        manifest, details = build({"workflow_runs": runs}, self.SHA)
        self.assertFalse(details["ready"])
        self.assertNotEqual(evaluate(manifest)["status"], "SOFTWARE_CEILING_PASS")

        runs.append(
            self.make_run(
                names[-1],
                run_number=99,
                status="in_progress",
                conclusion=None,
            )
        )
        manifest, details = build({"workflow_runs": runs}, self.SHA)
        self.assertFalse(details["ready"])
        self.assertNotEqual(evaluate(manifest)["status"], "SOFTWARE_CEILING_PASS")

    def test_failure_is_terminal_but_blocks_pass(self):
        runs = [
            self.make_run(name, run_number=index + 1)
            for index, name in enumerate(WORKFLOW_TO_GATES)
        ]
        runs[-1]["conclusion"] = "failure"
        manifest, details = build({"workflow_runs": runs}, self.SHA)
        self.assertTrue(details["ready"])
        result = evaluate(manifest)
        self.assertEqual(result["status"], "SOFTWARE_INCOMPLETE")
        self.assertTrue(result["failed"])

    def test_pull_request_run_cannot_substitute_for_push_evidence(self):
        names = list(WORKFLOW_TO_GATES)
        runs = [
            self.make_run(name, run_number=index + 1)
            for index, name in enumerate(names)
        ]
        target = names[0]
        runs = [run for run in runs if run["name"] != target]
        runs.append(self.make_run(target, run_number=100, event="pull_request"))
        manifest, details = build({"workflow_runs": runs}, self.SHA)
        self.assertFalse(details["ready"])
        self.assertNotEqual(evaluate(manifest)["status"], "SOFTWARE_CEILING_PASS")

    def test_latest_push_run_controls_gate(self):
        runs = [
            self.make_run(name, run_number=index + 1)
            for index, name in enumerate(WORKFLOW_TO_GATES)
        ]
        target = next(iter(WORKFLOW_TO_GATES))
        runs.append(self.make_run(target, run_number=200, conclusion="failure"))
        manifest, details = build({"workflow_runs": runs}, self.SHA)
        self.assertTrue(details["ready"])
        self.assertEqual(details["workflows"][target]["run_number"], 200)
        self.assertNotEqual(evaluate(manifest)["status"], "SOFTWARE_CEILING_PASS")


if __name__ == "__main__":
    unittest.main()
