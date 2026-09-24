#!/usr/bin/env python3
from __future__ import annotations
import argparse
import codecs
import json
import pathlib
import re

FAIL_LINE = re.compile(r"(?:--\s*FAILURE\s*$|:\s*\[FAILED\]\s*$)", re.IGNORECASE)
ERROR_COUNT = re.compile(r"\b(?:Errors?|Failures?)\.*\s*[:=]?\s*([0-9]+)\s*$", re.IGNORECASE)
PASS_LINE = re.compile(r"--\s*PASS\s*$", re.IGNORECASE)
WARN_LINE = re.compile(r"--\s*WARNING\s*$", re.IGNORECASE)


def decode_summary_bytes(data: bytes) -> str:
    """Decode SCT output without silently corrupting result markers.

    Official SCT Summary.log files are commonly UTF-16 with a BOM, while
    synthetic/unit-test fixtures are often UTF-8. Decode BOM-tagged text
    first, then strict UTF-8, and only infer BOM-less UTF-16 when the byte
    layout has a strong alternating-NUL signature.
    """
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16")
    if data.startswith(codecs.BOM_UTF8):
        return data.decode("utf-8-sig")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as utf8_error:
        sample = data[:4096]
        pairs = len(sample) // 2
        if pairs >= 8:
            even_nuls = sum(byte == 0 for byte in sample[0 : pairs * 2 : 2])
            odd_nuls = sum(byte == 0 for byte in sample[1 : pairs * 2 : 2])
            threshold = max(8, int(pairs * 0.30))
            if odd_nuls >= threshold and odd_nuls >= even_nuls * 4:
                return data.decode("utf-16-le")
            if even_nuls >= threshold and even_nuls >= odd_nuls * 4:
                return data.decode("utf-16-be")
        raise utf8_error


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
    positive_evidence = passes > 0
    return {
        "schema":"omni.sct-summary.v1",
        "passes_observed":passes,
        "warnings_observed":warnings,
        "explicit_failure_lines":explicit_failures,
        "nonzero_error_counts":error_counts,
        "failure_score":failures,
        "positive_evidence":positive_evidence,
        "status":"PASS" if failures == 0 and positive_evidence else "FAIL",
    }


def parse_path(path: pathlib.Path) -> dict[str, object]:
    return parse(decode_summary_bytes(path.read_bytes()))


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("summary")
    ap.add_argument("--json-out")
    ap.add_argument("--strict",action="store_true")
    ns=ap.parse_args()
    path=pathlib.Path(ns.summary)
    result=parse_path(path)
    output=json.dumps(result,indent=2,ensure_ascii=False)
    print(output)
    if ns.json_out:
        pathlib.Path(ns.json_out).write_text(output+"\n",encoding="utf-8")
    return 1 if ns.strict and result["status"] != "PASS" else 0

if __name__=="__main__":
    raise SystemExit(main())
