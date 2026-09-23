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

# These are top-level evidence groups. A group is PASS only when its own
# workflow has closed every internal gate. Missing groups are blockers.
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


def probe() -> dict[str, str | None]:
    return {
        name: next(
            (shutil.which(candidate) for candidate in candidates if shutil.which(candidate)),
            None,
        )
        for name, candidates in REQUIRED_TOOLS.items()
    }


def evaluate(statuses: Mapping[str, str]) -> dict[str, object]:
    normalized = {str(name): str(status).upper() for name, status in statuses.items()}
    missing = sorted(REQUIRED_GATES - normalized.keys())
    failed = sorted(
        name
        for name in REQUIRED_GATES & normalized.keys()
        if normalized[name] != "PASS"
    )
    blockers = sorted(set(missing) | set(failed))
    return {
        "status": "SOFTWARE_CEILING_PASS" if not blockers else "SOFTWARE_INCOMPLETE",
        "blockers": blockers,
        "missing": missing,
        "failed": failed,
        "required": sorted(REQUIRED_GATES),
    }
