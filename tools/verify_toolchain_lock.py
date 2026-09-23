#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(root: Path = ROOT) -> dict[str, object]:
    lock = json.loads((root / "toolchains.lock.json").read_text(encoding="utf-8"))
    checks = {
        ".github/workflows/workflow-lint.yml": [
            lock["actionlint"]["version"],
            lock["actionlint"]["linux_amd64_sha256"],
        ],
        ".github/workflows/formal-semantic-proof.yml": [
            f"cbmc-{lock['cbmc']['version']}",
            lock["cbmc"]["ubuntu_24_04_deb_sha256"],
            f"frama-c.{lock['frama_c']['version']}",
        ],
        ".github/workflows/deep-software-ceiling.yml": [
            lock["edk2_primary"]["tag"],
            lock["edk2_primary"]["commit"],
            f"cbmc-{lock['cbmc']['version']}",
            lock["cbmc"]["ubuntu_24_04_deb_sha256"],
            f"frama-c.{lock['frama_c']['version']}",
        ],
        ".github/workflows/reproducibility.yml": [
            lock["edk2_primary"]["tag"],
            lock["edk2_primary"]["commit"],
        ],
        ".github/workflows/hardware-hil.yml": [
            lock["edk2_primary"]["tag"],
            lock["edk2_primary"]["commit"],
        ],
        ".github/workflows/uefi-sct-build.yml": [
            lock["sct"]["edk2_tag"],
            lock["sct"]["edk2_commit"],
            lock["sct"]["tag"],
            lock["sct"]["commit"],
        ],
        ".github/workflows/uefi-sct-runtime.yml": [
            lock["sct"]["edk2_tag"],
            lock["sct"]["edk2_commit"],
            lock["sct"]["tag"],
            lock["sct"]["commit"],
        ],
    }
    missing=[]
    for relative,needles in checks.items():
        text=(root/relative).read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                missing.append({"file":relative,"value":needle})
    return {
        "schema":"omniexec.toolchain-lock-verification.v1",
        "status":"PASS" if not missing else "FAIL",
        "missing":missing,
        "checked_files":sorted(checks),
    }


def main() -> int:
    result=verify()
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["status"]=="PASS" else 1


if __name__=="__main__":
    raise SystemExit(main())
