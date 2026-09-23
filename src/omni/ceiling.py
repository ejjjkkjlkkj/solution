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

# Once every software gate is closed, uncertainty is allowed to remain only
# in phenomena that intrinsically require the physical target.
HARDWARE_ONLY_GATES = frozenset(
    {
        "physical_oem_uefi_execution",
        "physical_pre_os_keyboard_scan_and_focus_timing",
        "physical_hda_codec_topology",
        "physical_amplifier_eapd_path",
        "physical_speaker_speech_quality",
        "physical_interrupt_latency_and_jitter",
        "physical_tpm_quote_and_measurements",
        "oem_electrical_and_firmware_specific_behavior",
    }
)


def hardware_boundary() -> dict[str, object]:
    return {
        "status": "HARDWARE_ONLY",
        "software_changes_allowed": False,
        "remaining": sorted(HARDWARE_ONLY_GATES),
    }


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
        "remaining_hardware_gates": sorted(HARDWARE_ONLY_GATES) if not blockers else [],
    }
