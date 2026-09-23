#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(root: Path = ROOT) -> dict[str, object]:
    lock = json.loads((root / "toolchains.lock.json").read_text(encoding="utf-8"))
    checks: dict[str, list[str]] = {
        ".github/workflows/workflow-lint.yml": [
            lock["actionlint"]["version"],
            lock["actionlint"]["linux_amd64_sha256"],
        ],
        ".github/workflows/formal-semantic-proof.yml": [
            f"cbmc-{lock['cbmc']['version']}",
            lock["cbmc"]["ubuntu_24_04_deb_sha256"],
            "scripts/install_pinned_framac.sh",
        ],
        ".github/workflows/deep-software-ceiling.yml": [
            lock["edk2_primary"]["tag"],
            lock["edk2_primary"]["commit"],
            f"cbmc-{lock['cbmc']['version']}",
            lock["cbmc"]["ubuntu_24_04_deb_sha256"],
            "scripts/install_pinned_framac.sh",
            "scripts/build_pinned_qemu.sh",
        ],
        ".github/workflows/reproducibility.yml": [
            lock["edk2_primary"]["tag"],
            lock["edk2_primary"]["commit"],
        ],
        ".github/workflows/hardware-hil.yml": [
            lock["edk2_primary"]["tag"],
            lock["edk2_primary"]["commit"],
            "scripts/build_pinned_qemu.sh",
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
            "scripts/build_pinned_qemu.sh",
        ],
        "scripts/install_pinned_framac.sh": [
            lock["formal"]["opam_repository_sha"],
            lock["formal"]["ocaml_package"],
            lock["formal"]["frama_c_package"],
            lock["formal"]["alt_ergo_package"],
        ],
        "scripts/build_pinned_qemu.sh": [
            f'QEMU_VERSION="{lock["qemu"]["version"]}"',
            lock["qemu"]["release_key_fingerprint"],
        ],
    }

    missing: list[dict[str, str]] = []
    for relative, needles in checks.items():
        path = root / relative
        if not path.is_file():
            missing.append({"file": relative, "value": "<file missing>"})
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                missing.append({"file": relative, "value": needle})

    return {
        "schema": "omniexec.toolchain-lock-verification.v2",
        "status": "PASS" if not missing else "FAIL",
        "missing": missing,
        "checked_files": sorted(checks),
    }


def main() -> int:
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
