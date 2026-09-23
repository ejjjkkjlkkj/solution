from __future__ import annotations
import shutil

REQUIRED_TOOLS = {
    "python": ("python3", "python"),
    "clang": ("clang",),
    "llvm-cov": ("llvm-cov",),
    "llvm-profdata": ("llvm-profdata",),
    "qemu": ("qemu-system-x86_64",),
    "cbmc": ("cbmc",),
    "frama-c": ("frama-c",),
}

def probe() -> dict[str, str | None]:
    return {name: next((shutil.which(candidate) for candidate in candidates if shutil.which(candidate)), None) for name, candidates in REQUIRED_TOOLS.items()}

def evaluate(statuses: dict[str, str]) -> dict[str, object]:
    blockers = sorted(name for name, status in statuses.items() if status != "PASS")
    return {"status": "SOFTWARE_CEILING_PASS" if not blockers else "SOFTWARE_INCOMPLETE", "blockers": blockers}
