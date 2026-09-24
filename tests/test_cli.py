import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from omni import ceiling, cli


class CliExitStatusTests(unittest.TestCase):
    def _run_hardware_boundary(self, manifest: dict[str, str]) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hardware.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with patch("sys.argv", ["omni", "hardware-boundary", str(path)]):
                with redirect_stdout(io.StringIO()):
                    return cli.main()

    def test_incomplete_hardware_boundary_exits_nonzero(self):
        self.assertEqual(self._run_hardware_boundary({}), 1)

    def test_complete_hardware_boundary_exits_zero(self):
        manifest = {gate: "PASS" for gate in ceiling.HARDWARE_GATES}
        self.assertEqual(self._run_hardware_boundary(manifest), 0)


if __name__ == "__main__":
    unittest.main()
