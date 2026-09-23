from __future__ import annotations

import json
import pathlib
import shutil
from collections.abc import Mapping, Sequence

REQUIRED_TOOLS = {
    "python": ("python3", "python"),
    "clang": ("clang",),
    "llvm-cov": ("llvm-cov",),
    "llvm-profdata": ("llvm-profdata",),
    "qemu": ("qemu-system-x86_64",),
    "cbmc": ("cbmc",),
    "frama-c": ("frama-c",),
}

MANIFEST_SCHEMA = "omni.software-ceiling.v1"
ALLOWED_STATUSES = frozenset({"PASS", "FAIL", "NOT_RUN", "SKIP", "BLOCKED"})

# These identifiers are intentionally code-owned. A status manifest is evidence,
# not policy, so it cannot weaken the required gate set.
REQUIRED_SOFTWARE_GATES: tuple[str, ...] = (
    "python-tests",
    "native-diagnostics",
    "asan",
    "ubsan",
    "native-coverage",
    "fuzz-100k",
    "cbmc",
    "frama-c-eva",
    "frama-c-wp",
    "compiler-differential",
    "edk2-host-tests",
    "uefi-edk2-build",
    "qemu-ovmf-execution",
    "qemu-record-replay",
    "native-reproducibility",
    "uefi-reproducibility",
    "provenance-attestation",
    "uefi-sct-build",
    "uefi-sct-execution",
)


def probe() -> dict[str, str | None]:
    return {
        name: next(
            (
                shutil.which(candidate)
                for candidate in candidates
                if shutil.which(candidate)
            ),
            None,
        )
        for name, candidates in REQUIRED_TOOLS.items()
    }


def _validate_status_mapping(statuses: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for name, status in statuses.items():
        if not isinstance(name, str) or not name:
            raise ValueError("gate names must be non-empty strings")
        if not isinstance(status, str):
            raise ValueError(f"gate {name!r} status must be a string")
        normalized[name] = status
    return normalized


def evaluate(
    statuses: Mapping[str, str],
    *,
    required: Sequence[str] = REQUIRED_SOFTWARE_GATES,
) -> dict[str, object]:
    """Evaluate the software ceiling without permitting policy weakening.

    PASS is possible only when every code-owned required gate is present and
    exactly PASS. Empty, partial, skipped, blocked, failed, or invalid evidence
    is always incomplete.
    """

    supplied = _validate_status_mapping(statuses)
    required_tuple = tuple(required)
    if not required_tuple or len(set(required_tuple)) != len(required_tuple):
        raise ValueError("required gate set must be non-empty and unique")

    missing = sorted(name for name in required_tuple if name not in supplied)
    invalid = {
        name: supplied[name]
        for name in required_tuple
        if name in supplied and supplied[name] not in ALLOWED_STATUSES
    }
    non_pass = {
        name: supplied[name]
        for name in required_tuple
        if name in supplied
        and supplied[name] in ALLOWED_STATUSES
        and supplied[name] != "PASS"
    }
    unexpected = sorted(name for name in supplied if name not in required_tuple)
    blockers = sorted(set(missing) | set(invalid) | set(non_pass))

    return {
        "schema": MANIFEST_SCHEMA,
        "status": "SOFTWARE_CEILING_PASS" if not blockers else "SOFTWARE_INCOMPLETE",
        "required": list(required_tuple),
        "blockers": blockers,
        "missing": missing,
        "non_pass": non_pass,
        "invalid": invalid,
        "unexpected": unexpected,
        "evidence_count": len(supplied),
    }


def load_manifest(path: str | pathlib.Path) -> dict[str, object]:
    payload = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest root must be an object")
    if payload.get("schema") != MANIFEST_SCHEMA:
        raise ValueError(
            f"manifest schema must be {MANIFEST_SCHEMA!r}, got {payload.get('schema')!r}"
        )
    statuses = payload.get("statuses")
    if not isinstance(statuses, dict):
        raise ValueError("manifest statuses must be an object")
    if "required" in payload:
        raise ValueError("manifest cannot override the code-owned required gate set")
    return payload


def evaluate_manifest(path: str | pathlib.Path) -> dict[str, object]:
    payload = load_manifest(path)
    result = evaluate(payload["statuses"])  # type: ignore[arg-type]
    if "evidence" in payload:
        result["evidence"] = payload["evidence"]
    return result
