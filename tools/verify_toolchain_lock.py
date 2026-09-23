#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _string(lock: dict[str, Any], section: str, key: str) -> str:
    value = lock.get(section, {}).get(key) if isinstance(lock.get(section), dict) else None
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid {section}.{key}")
    return value


def _validate_lock(lock: dict[str, Any]) -> list[dict[str, str]]:
    invalid: list[dict[str, str]] = []
    hex40 = [
        ("edk2_primary", "commit"),
        ("sct", "edk2_commit"),
        ("sct", "commit"),
        ("formal", "opam_repository_sha"),
        ("qemu", "release_key_fingerprint"),
    ]
    hex64 = [
        ("cbmc", "ubuntu_24_04_deb_sha256"),
        ("qemu", "tarball_sha256"),
        ("actionlint", "linux_amd64_sha256"),
    ]
    for section, key in hex40:
        try:
            value = _string(lock, section, key)
        except ValueError as exc:
            invalid.append({"field": f"{section}.{key}", "value": str(exc)})
            continue
        if not HEX40_RE.fullmatch(value):
            invalid.append({"field": f"{section}.{key}", "value": value})
    for section, key in hex64:
        try:
            value = _string(lock, section, key)
        except ValueError as exc:
            invalid.append({"field": f"{section}.{key}", "value": str(exc)})
            continue
        if not HEX64_RE.fullmatch(value):
            invalid.append({"field": f"{section}.{key}", "value": value})

    actions = lock.get("github_actions")
    if not isinstance(actions, dict) or not actions:
        invalid.append({"field": "github_actions", "value": "missing or invalid mapping"})
    else:
        for key, value in sorted(actions.items()):
            if not isinstance(value, str) or not HEX40_RE.fullmatch(value):
                invalid.append({"field": f"github_actions.{key}", "value": str(value)})
    return invalid


def verify(root: Path = ROOT) -> dict[str, object]:
    try:
        raw = json.loads((root / "toolchains.lock.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema": "omniexec.toolchain-lock-verification.v3",
            "status": "FAIL",
            "missing": [],
            "invalid": [{"field": "toolchains.lock.json", "value": str(exc)}],
            "checked_files": [],
        }
    if not isinstance(raw, dict):
        return {
            "schema": "omniexec.toolchain-lock-verification.v3",
            "status": "FAIL",
            "missing": [],
            "invalid": [{"field": "toolchains.lock.json", "value": "root must be an object"}],
            "checked_files": [],
        }
    lock: dict[str, Any] = raw
    invalid = _validate_lock(lock)
    if invalid:
        return {
            "schema": "omniexec.toolchain-lock-verification.v3",
            "status": "FAIL",
            "missing": [],
            "invalid": invalid,
            "checked_files": [],
        }

    checks: dict[str, list[str]] = {
        ".github/workflows/workflow-lint.yml": [
            _string(lock, "actionlint", "version"),
            _string(lock, "actionlint", "linux_amd64_sha256"),
        ],
        ".github/workflows/formal-semantic-proof.yml": [
            f"cbmc-{_string(lock, 'cbmc', 'version')}",
            _string(lock, "cbmc", "ubuntu_24_04_deb_sha256"),
            "scripts/install_pinned_framac.sh",
        ],
        ".github/workflows/deep-software-ceiling.yml": [
            _string(lock, "edk2_primary", "tag"),
            _string(lock, "edk2_primary", "commit"),
            f"cbmc-{_string(lock, 'cbmc', 'version')}",
            _string(lock, "cbmc", "ubuntu_24_04_deb_sha256"),
            "scripts/install_pinned_framac.sh",
            "scripts/build_pinned_qemu.sh",
        ],
        ".github/workflows/reproducibility.yml": [
            _string(lock, "edk2_primary", "tag"),
            _string(lock, "edk2_primary", "commit"),
        ],
        ".github/workflows/hardware-hil.yml": [
            _string(lock, "edk2_primary", "tag"),
            _string(lock, "edk2_primary", "commit"),
            "scripts/build_pinned_qemu.sh",
        ],
        ".github/workflows/uefi-sct-build.yml": [
            _string(lock, "sct", "edk2_tag"),
            _string(lock, "sct", "edk2_commit"),
            _string(lock, "sct", "tag"),
            _string(lock, "sct", "commit"),
        ],
        ".github/workflows/uefi-sct-runtime.yml": [
            _string(lock, "sct", "edk2_tag"),
            _string(lock, "sct", "edk2_commit"),
            _string(lock, "sct", "tag"),
            _string(lock, "sct", "commit"),
            "scripts/build_pinned_qemu.sh",
        ],
        "scripts/install_pinned_framac.sh": [
            _string(lock, "formal", "opam_repository_sha"),
            _string(lock, "formal", "ocaml_package"),
            _string(lock, "formal", "frama_c_package"),
            _string(lock, "formal", "alt_ergo_package"),
        ],
        "scripts/build_pinned_qemu.sh": [
            f'QEMU_VERSION="{_string(lock, "qemu", "version")}"',
            f'QEMU_RELEASE_KEY_FPR="{_string(lock, "qemu", "release_key_fingerprint")}"',
            f'QEMU_TARBALL_SHA256="{_string(lock, "qemu", "tarball_sha256")}"',
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
        "schema": "omniexec.toolchain-lock-verification.v3",
        "status": "PASS" if not missing else "FAIL",
        "missing": missing,
        "invalid": [],
        "checked_files": sorted(checks),
    }


def main() -> int:
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
