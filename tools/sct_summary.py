#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re

FAIL_LINE = re.compile(r"(?:--\s*FAILURE\s*$|:\s*\[FAILED\]\s*$)", re.IGNORECASE)
ERROR_COUNT = re.compile(
    r"\b(?:Errors?|Failures?)\.*\s*[:=]?\s*([0-9]+)\s*$",
    re.IGNORECASE,
)
PASS_LINE = re.compile(r"--\s*PASS\s*$", re.IGNORECASE)
WARN_LINE = re.compile(r"--\s*WARNING\s*$", re.IGNORECASE)


def parse(text: str) -> dict[str, object]:
    explicit_failures: list[dict[str, object]] = []
    error_counts: list[dict[str, object]] = []
    passes = 0
    warnings = 0
    nonblank_lines = 0

    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.rstrip()
        if stripped.strip():
            nonblank_lines += 1
        if FAIL_LINE.search(stripped):
            explicit_failures.append({"line": number, "text": stripped[-500:]})
        match = ERROR_COUNT.search(stripped)
        if match and int(match.group(1)) > 0:
            error_counts.append(
                {
                    "line": number,
                    "count": int(match.group(1)),
                    "text": stripped[-500:],
                }
            )
        if PASS_LINE.search(stripped):
            passes += 1
        if WARN_LINE.search(stripped):
            warnings += 1

    failure_score = len(explicit_failures) + sum(
        int(item["count"]) for item in error_counts
    )
    blockers: list[str] = []
    if not text.strip():
        blockers.append("EMPTY_SUMMARY")
    if passes == 0:
        blockers.append("NO_PASS_RESULT")
    if failure_score:
        blockers.append("FAILURES_OBSERVED")
    if "�" in text:
        blockers.append("DECODE_REPLACEMENT_OBSERVED")

    return {
        "schema": "omni.sct-summary.v1",
        "passes_observed": passes,
        "warnings_observed": warnings,
        "nonblank_lines": nonblank_lines,
        "explicit_failure_lines": explicit_failures,
        "nonzero_error_counts": error_counts,
        "failure_score": failure_score,
        "blockers": blockers,
        "status": "PASS" if not blockers else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary")
    parser.add_argument("--json-out")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    path = pathlib.Path(args.summary)
    result = parse(path.read_text(encoding="utf-8", errors="replace"))
    output = json.dumps(result, indent=2, ensure_ascii=False)
    print(output)

    if args.json_out:
        pathlib.Path(args.json_out).write_text(output + "\n", encoding="utf-8")

    return 1 if args.strict and result["status"] != "PASS" else 0


if __name__ == "__main__":
    raise SystemExit(main())
