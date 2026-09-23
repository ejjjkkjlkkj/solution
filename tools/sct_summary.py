#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import pathlib
import re

FAIL_LINE = re.compile(r"(?:--\s*FAILURE\s*$|:\s*\[FAILED\]\s*$)", re.IGNORECASE)
ERROR_COUNT = re.compile(r"\b(?:Errors?|Failures?)\.*\s*[:=]?\s*([0-9]+)\s*$", re.IGNORECASE)
PASS_LINE = re.compile(r"--\s*PASS\s*$", re.IGNORECASE)
WARN_LINE = re.compile(r"--\s*WARNING\s*$", re.IGNORECASE)

def parse(text: str) -> dict[str, object]:
    explicit_failures=[]
    error_counts=[]
    passes=0
    warnings=0
    for number,line in enumerate(text.splitlines(),1):
        stripped=line.rstrip()
        if FAIL_LINE.search(stripped):
            explicit_failures.append({"line":number,"text":stripped[-500:]})
        m=ERROR_COUNT.search(stripped)
        if m and int(m.group(1)) > 0:
            error_counts.append({"line":number,"count":int(m.group(1)),"text":stripped[-500:]})
        if PASS_LINE.search(stripped):
            passes += 1
        if WARN_LINE.search(stripped):
            warnings += 1
    failures=len(explicit_failures)+sum(x["count"] for x in error_counts)
    return {
        "schema":"omni.sct-summary.v1",
        "passes_observed":passes,
        "warnings_observed":warnings,
        "explicit_failure_lines":explicit_failures,
        "nonzero_error_counts":error_counts,
        "failure_score":failures,
        "status":"PASS" if failures == 0 else "FAIL",
    }

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("summary")
    ap.add_argument("--json-out")
    ap.add_argument("--strict",action="store_true")
    ns=ap.parse_args()
    path=pathlib.Path(ns.summary)
    result=parse(path.read_text(encoding="utf-8",errors="replace"))
    output=json.dumps(result,indent=2,ensure_ascii=False)
    print(output)
    if ns.json_out:
        pathlib.Path(ns.json_out).write_text(output+"\n",encoding="utf-8")
    return 1 if ns.strict and result["status"] != "PASS" else 0

if __name__=="__main__":
    raise SystemExit(main())
