#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re

STAT_KEYS = {"OMNI_HII_HANDLES","OMNI_HII_FORM_PACKAGES","OMNI_HII_OPCODES","OMNI_HII_QUESTIONS","OMNI_HII_PASSWORDS","OMNI_HII_INVALID"}
MARKERS = {"OMNI_EVIDENCE_V1","OMNI_HII_PASS","OMNI_UEFI_PASS"}
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

class EvidenceError(ValueError):
    pass

def sha256_file(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_evidence(text: str) -> tuple[set[str], dict[str,int]]:
    markers=set()
    stats={}
    for raw in text.splitlines():
        line=raw.strip()
        if not line:
            continue
        if "\\x00" in line:
            raise EvidenceError("NUL byte in evidence")
        if line.endswith("_FAIL"):
            raise EvidenceError(f"firmware reported failure: {line}")
        if line in MARKERS:
            if line in markers:
                raise EvidenceError(f"duplicate marker: {line}")
            markers.add(line)
            continue
        if "=" not in line:
            raise EvidenceError(f"unknown evidence line: {line}")
        key,value=line.split("=",1)
        if key not in STAT_KEYS:
            raise EvidenceError(f"unknown evidence key: {key}")
        if key in stats:
            raise EvidenceError(f"duplicate evidence key: {key}")
        if not value.isdecimal():
            raise EvidenceError(f"non-decimal evidence value: {key}={value}")
        stats[key]=int(value)
    missing_markers=MARKERS-markers
    if missing_markers:
        raise EvidenceError(f"missing markers: {sorted(missing_markers)}")
    missing_stats=STAT_KEYS-stats.keys()
    if missing_stats:
        raise EvidenceError(f"missing stats: {sorted(missing_stats)}")
    if stats["OMNI_HII_HANDLES"] <= 0:
        raise EvidenceError("no HII handles observed")
    if stats["OMNI_HII_FORM_PACKAGES"] <= 0:
        raise EvidenceError("no HII form package observed")
    if stats["OMNI_HII_OPCODES"] <= 0:
        raise EvidenceError("no IFR opcode observed")
    if stats["OMNI_HII_INVALID"] != 0:
        raise EvidenceError("invalid HII package observed")
    return markers,stats

def verify(evidence_path: pathlib.Path, efi_path: pathlib.Path, expected_sha256: str) -> dict[str,object]:
    if not SHA256_RE.fullmatch(expected_sha256):
        raise EvidenceError("expected SHA-256 must be 64 hexadecimal characters")
    try:
        text=evidence_path.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError("evidence is not ASCII") from exc
    _,stats=parse_evidence(text)
    actual=sha256_file(efi_path)
    expected=expected_sha256.lower()
    if actual != expected:
        raise EvidenceError(f"EFI SHA-256 mismatch: actual={actual} expected={expected}")
    return {"status":"PHYSICAL_EVIDENCE_SOFTWARE_VERIFY_PASS","efi_sha256":actual,"stats":stats}

def main() -> int:
    ap=argparse.ArgumentParser(description="Fail-closed OmniProbe physical evidence verifier")
    ap.add_argument("--evidence",required=True,type=pathlib.Path)
    ap.add_argument("--efi",required=True,type=pathlib.Path)
    ap.add_argument("--expected-sha256",required=True)
    ns=ap.parse_args()
    try:
        result=verify(ns.evidence,ns.efi,ns.expected_sha256)
    except (OSError,EvidenceError) as exc:
        print(json.dumps({"status":"FAIL","error":str(exc)},sort_keys=True))
        return 1
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
