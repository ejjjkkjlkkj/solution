import json
import tempfile
import unittest
from pathlib import Path

from omni.ceiling import (
    MANIFEST_SCHEMA,
    REQUIRED_SOFTWARE_GATES,
    evaluate_manifest,
    load_manifest,
)


class CeilingManifestTests(unittest.TestCase):
    def write_manifest(self, directory: str, payload: object) -> Path:
        path = Path(directory) / "ceiling.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_complete_manifest_passes(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.write_manifest(
                td,
                {
                    "schema": MANIFEST_SCHEMA,
                    "statuses": {
                        name: "PASS" for name in REQUIRED_SOFTWARE_GATES
                    },
                    "evidence": {"run": "unit-test"},
                },
            )
            result = evaluate_manifest(path)
            self.assertEqual(result["status"], "SOFTWARE_CEILING_PASS")
            self.assertEqual(result["evidence"]["run"], "unit-test")

    def test_manifest_cannot_override_policy(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.write_manifest(
                td,
                {
                    "schema": MANIFEST_SCHEMA,
                    "required": ["asan"],
                    "statuses": {"asan": "PASS"},
                },
            )
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_wrong_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.write_manifest(
                td,
                {
                    "schema": "omni.software-ceiling.v0",
                    "statuses": {},
                },
            )
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_missing_statuses_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.write_manifest(td, {"schema": MANIFEST_SCHEMA})
            with self.assertRaises(ValueError):
                load_manifest(path)


if __name__ == "__main__":
    unittest.main()
