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

REQUIRED_SOFTWARE_GATES = frozenset(
    {
        "core_semantics",
        "native_verification",
        "deep_software_verification",
        "deep_regression_gates",
        "independent_verification",
        "formal_semantic_proof",
        "ifr_parser_fuzz",
        "ci_workflow_lint",
        "reproducibility_and_provenance",
        "uefi_sct_build",
        "uefi_sct_runtime_ovmf",
        "physical_evidence_verifier",
    }
)
REQUIRED_GATES = REQUIRED_SOFTWARE_GATES

HARDWARE_GATES = frozenset(
    {
        "windows_qemu_hil",
        "windows_vmware_hil",
        "asus_oem_uefi",
        "physical_keyboard",
        "physical_hda_audio",
        "physical_latency",
        "tpm_quote",
    }
)

ALLOWED_STATUSES = frozenset(
    {
        "PASS","FAIL","FAILURE","NOT_RUN","MISSING","BLOCKED","SKIP","SKIPPED",
        "CANCELLED","TIMED_OUT","ACTION_REQUIRED","NEUTRAL","STALE",
    }
)

def probe() -> dict[str, str | None]:
    return {
        name: next((shutil.which(candidate) for candidate in candidates if shutil.which(candidate)), None)
        for name, candidates in REQUIRED_TOOLS.items()
    }

def _evaluate_exact(statuses: Mapping[str, str], required: frozenset[str], pass_name: str, incomplete_name: str) -> dict[str, object]:
    supplied: dict[str, str] = {}
    for name, status in statuses.items():
        if not isinstance(name, str) or not name:
            raise ValueError("gate names must be non-empty strings")
        if not isinstance(status, str):
            raise ValueError(f"gate {name!r} status must be a string")
        supplied[name] = status

    missing = sorted(required - supplied.keys())
    unexpected = sorted(supplied.keys() - required)
    invalid = sorted(name for name in required & supplied.keys() if supplied[name] not in ALLOWED_STATUSES)
    failed = sorted(name for name in required & supplied.keys() if supplied[name] in ALLOWED_STATUSES and supplied[name] != "PASS")
    blockers = sorted(set(missing) | set(unexpected) | set(invalid) | set(failed))
    return {
        "status": pass_name if not blockers else incomplete_name,
        "blockers": blockers,
        "missing": missing,
        "failed": failed,
        "invalid": invalid,
        "unexpected": unexpected,
        "required": sorted(required),
        "evidence_count": len(supplied),
    }

def evaluate(statuses: Mapping[str, str]) -> dict[str, object]:
    return _evaluate_exact(statuses, REQUIRED_SOFTWARE_GATES, "SOFTWARE_CEILING_PASS", "SOFTWARE_INCOMPLETE")

def evaluate_hardware(statuses: Mapping[str, str]) -> dict[str, object]:
    return _evaluate_exact(statuses, HARDWARE_GATES, "HARDWARE_BOUNDARY_PASS", "HARDWARE_EVIDENCE_INCOMPLETE")

# ---------------------------------------------------------------------------
# Chain accessibilite + securite : optionnel, evalue en runtime
# ---------------------------------------------------------------------------
# Ces gates ne sont PAS dans REQUIRED_SOFTWARE_GATES : ils sont valides en
# runtime via `omni chain-report` / `omni host-scan` / `omni uefi211-check`.
# Ils refletent la disponibilite locale des outils d'accessibilite et de la
# pile reseau (VPN / IDS / IPS) -- ce qui depend de la machine hote, pas
# uniquement du code.

CHAIN_GATE_KEYS: frozenset[str] = frozenset(
    {
        # Firmware UEFI 2.10/2.11
        "uefi_211_hii",
        "uefi_211_audio",
        "uefi_211_input",
        "uefi_211_network",
        # Host chain (run-time)
        "host_a11y",
        "host_vpn",
        "host_ids",
        "host_ips",
        # Aggregat
        "end_to_end_chain",
    }
)


def evaluate_chain(stage_statuses: Mapping[str, str]) -> dict[str, object]:
    """Evalue les gates de la chaine accessibilite/securite (optionnels).

    Les cles sont celles de CHAIN_GATE_KEYS. Toutes les cles doivent etre
    fournies ; toute valeur non PASS bloque le verdict.

    Le verdict final est isole : SOFTWARE_CEILING_PASS n'est pas affecte par
    ces gates (qui dependent du materiel hote).
    """
    return _evaluate_exact(
        stage_statuses,
        CHAIN_GATE_KEYS,
        "CHAIN_REPORT_PASS",
        "CHAIN_REPORT_INCOMPLETE",
    )
