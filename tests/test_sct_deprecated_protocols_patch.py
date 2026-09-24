from __future__ import annotations

import unittest
from pathlib import Path

from tools.patch_sct_deprecated_protocols import PATCHES, patch_text


class SctDeprecatedProtocolPatchTests(unittest.TestCase):
    def test_every_backport_line_is_removed_exactly_once(self) -> None:
        for path, expected_lines in PATCHES.items():
            source = "\r\n".join(("before", *expected_lines, "after", ""))
            result = patch_text(source, expected_lines, path)
            for expected in expected_lines:
                self.assertNotIn(expected, {line.rstrip("\r\n") for line in result.splitlines(keepends=True)})
            self.assertIn("before\r\n", result)
            self.assertIn("after\r\n", result)

    def test_missing_line_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            patch_text("before\n", ("required line",), "synthetic")

    def test_duplicate_line_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            patch_text("x\nx\n", ("x",), "synthetic")

    def test_both_sct_workflows_apply_deprecated_protocol_patch(self) -> None:
        command = "python3 tools/patch_sct_deprecated_protocols.py SctPkg"
        for path in (
            Path(".github/workflows/uefi-sct-build.yml"),
            Path(".github/workflows/uefi-sct-runtime.yml"),
        ):
            text = path.read_text(encoding="utf-8")
            self.assertIn(command, text)
            self.assertLess(
                text.index("python3 tools/patch_sct_efi_header.py SctPkg/Include/Efi.h"),
                text.index(command),
            )


if __name__ == "__main__":
    unittest.main()
