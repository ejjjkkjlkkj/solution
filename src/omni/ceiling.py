from __future__ import annotations

import shutil
from collections.abc import Mapping

REQUIRED_TOOLS = {
    "python": ("python3", "python"),
    "clang": ("clang",),
    "llvm-cov": ("llvm-cov",),
    "llvm-profdata": ("llvm-profdata",),
    "qemu": ("qemu-system-x86_64",),
    "cbmc": ("cbmc",),
    "frama-c": ("frama-c",),
}

REQUIRED_GATES = frozenset(
    {
        "core_semantics",
        "native_verification",
        "deep_software_verification",
        "reproducibility_and_provenance",
        "uefi_sct_build",
        "uefi_sct_runtime_ovmf",
        "windows_qemu_hil",
        "windows_vmware_hil",
        "physical_evidence_verifier",
    }
)

ALLOWED_STATUSES = frozenset(
    {
        "PASS",
        "FAIL",
        "FAILURE",
        "NOT_RUN",
        "MISSING",
        "BLOCKED",
        "SKIP",
        "SKIPPED",
        "CANCELLED",
        "TIMED_OUT",
        "ACTION_REQUIRED",
        "NEUTRAL",
        "STALE",
    }
)


def probe() -> dict[str, str | None]:
    return {
        name: next(
            (shutil.which(candidate) for candidate in candidates if shutil.which(candidate)),
            None,
        )
        for name, candidates in REQUIRED_TOOLS.items()
    }


def evaluate(statuses: Mapping[str, str]) -> dict[str, object]:
    supplied: dict[str, str] = {}
    for name, status in statuses.items():
        if not isinstance(name, str) or not name:
            raise ValueError("gate names must be non-empty strings")
        if not isinstance(status, str):
            raise ValueError(f"gate {name!r} status must be a string")
        supplied[name] = status

    missing = sorted(REQUIRED_GATES - supplied.keys())
    unexpected = sorted(supplied.keys() - REQUIRED_GATES)
    invalid = sorted(
        name
        for name in REQUIRED_GATES & supplied.keys()
        if supplied[name] not in ALLOWED_STATUSES
    )
    failed = sorted(
        name
        for name in REQUIRED_GATES & supplied.keys()
        if supplied[name] in ALLOWED_STATUSES and supplied[name] != "PASS"
    )

    blockers = sorted(set(missing) | set(unexpected) | set(invalid) | set(failed))
    return {
        "status": "SOFTWARE_CEILING_PASS" if not blockers else "SOFTWARE_INCOMPLETE",
        "blockers": blockers,
        "missing": missing,
        "failed": failed,
        "invalid": invalid,
        "unexpected": unexpected,
        "required": sorted(REQUIRED_GATES),
        "evidence_count": len(supplied),
    }
