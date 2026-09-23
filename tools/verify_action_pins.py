#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USES_RE = re.compile(r"\buses:\s*([^\s#]+)")
PINNED_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-fA-F]{40}$")


def verify() -> dict[str, object]:
    violations: list[dict[str, str]] = []
    checked = 0
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_RE.search(line)
            if not match:
                continue
            value = match.group(1)
            checked += 1
            if value.startswith("./") or value.startswith("docker://"):
                continue
            if not PINNED_RE.fullmatch(value):
                violations.append(
                    {
                        "file": path.relative_to(ROOT).as_posix(),
                        "line": str(line_number),
                        "uses": value,
                    }
                )
    return {
        "schema": "omniexec.action-pins.v1",
        "status": "PASS" if not violations else "FAIL",
        "checked": checked,
        "violations": violations,
    }


def main() -> int:
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
