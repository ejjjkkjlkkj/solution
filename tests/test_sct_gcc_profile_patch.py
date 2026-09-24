from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.patch_sct_gcc_profile import (
    LEGACY_TOOLCHAIN_SELECTION,
    MODERN_TOOLCHAIN_SELECTION,
    patch_text,
)


class SctGccProfilePatchTests(unittest.TestCase):
    def test_pinned_legacy_selector_becomes_modern_gcc(self) -> None:
        source = "before\n" + LEGACY_TOOLCHAIN_SELECTION + "\nafter\n"
        result = patch_text(source)

        self.assertNotIn(LEGACY_TOOLCHAIN_SELECTION, result)
        self.assertEqual(result.count(MODERN_TOOLCHAIN_SELECTION), 1)
        self.assertIn("before\n", result)
        self.assertIn("\nafter\n", result)

    def test_missing_or_drifted_selector_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            patch_text("export TARGET_TOOLS=GCC5\n")

    def test_duplicate_selector_fails_closed(self) -> None:
        text = LEGACY_TOOLCHAIN_SELECTION + "\n" + LEGACY_TOOLCHAIN_SELECTION
        with self.assertRaises(ValueError):
            patch_text(text)

    def test_workflows_use_modern_sct_output_directory(self) -> None:
        for path in (
            Path(".github/workflows/uefi-sct-build.yml"),
            Path(".github/workflows/uefi-sct-runtime.yml"),
        ):
            text = path.read_text(encoding="utf-8")
            self.assertIn("python3 tools/patch_sct_gcc_profile.py SctPkg/build.sh", text)
            self.assertIn("Build/UefiSct/RELEASE_GCC/SctPackageX64", text)
            self.assertNotIn("RELEASE_GCC5", text)


if __name__ == "__main__":
    unittest.main()
