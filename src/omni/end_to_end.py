"""
Orchestrateur de bout en bout : firmware UEFI -> boot -> OS -> reseau.

Combine les modules `uefi211` (couvre les protocoles UEFI 2.10/2.11 embarques
dans le firmware) et `host_chain` (couvre l'accessibilite OS et la pile de
securite reseau cote hote). Le rapport produit est exploitable directement
par le CLI et le `software-ceiling` aggregator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from . import host_chain, uefi211


# ---------------------------------------------------------------------------
# Configuration : categorie -> etape de la chaine
# ---------------------------------------------------------------------------

CHAIN_STAGES: tuple[str, ...] = (
    "uefi_firmware",     # Image UEFI analysee
    "uefi_accessibility", # HII + Audio + Input UEFI 2.10/2.11
    "uefi_network",      # HTTP / REST / TCP / DHCPv6 (cleer transport layer)
    "os_accessibility",  # Screen readers installes sur l'OS hote
    "network_security", # VPN hote (chainage confidentiel)
    "intrusion",         # IDS / IPS hote (chainage securite)
)


_STAGE_CATEGORY_MAP: dict[str, tuple[str, ...]] = {
    "uefi_firmware":     ("hii",),                 # un firmware "accessible" doit avoir HII
    "uefi_accessibility":("hii", "audio", "input"),
    "uefi_network":      ("network",),
    "os_accessibility":  ("a11y",),
    "network_security":  ("vpn",),
    "intrusion":         ("ids",),
}


_STAGE_LABELS: dict[str, str] = {
    "uefi_firmware":      "Firmware UEFI charge",
    "uefi_accessibility": "Accessibilite pre-OS (UEFI 2.10/2.11)",
    "uefi_network":       "Stack reseau UEFI (transport)",
    "os_accessibility":   "Accessibilite OS (screen reader)",
    "network_security":   "Confidentialite reseau (VPN)",
    "intrusion":          "Detection / prevention d'intrusion",
}


# ---------------------------------------------------------------------------
# Resultat
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class StageReport:
    stage: str
    label: str
    status: str           # OK / PARTIEL / ABSENT / UNKNOWN
    matched: int
    expected: int
    keys: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "label": self.label,
            "status": self.status,
            "matched": self.matched,
            "expected": self.expected,
            "keys": list(self.keys),
        }


@dataclass(frozen=True, slots=True)
class ChainReport:
    firmware_bytes: int
    firmware_sha256: str
    uefi_version: str
    host_platform: str
    stages: tuple[StageReport, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "firmware": {
                "bytes_total": self.firmware_bytes,
                "sha256": self.firmware_sha256,
                "uefi_version": self.uefi_version,
            },
            "host": {
                "platform": self.host_platform,
            },
            "stages": [s.as_dict() for s in self.stages],
            "passed": self.passed(),
        }

    def passed(self, required: tuple[str, ...] = CHAIN_STAGES) -> bool:
        """PASS strict : toutes les etapes doivent etre OK (pas ABSENT)."""
        by_stage = {s.stage: s for s in self.stages}
        return all(by_stage[stage].status == "OK" for stage in required)

    def stage(self, name: str) -> StageReport | None:
        for s in self.stages:
            if s.stage == name:
                return s
        return None


# ---------------------------------------------------------------------------
# Construction du rapport
# ---------------------------------------------------------------------------

def _status(matched: int, expected: int) -> str:
    if expected <= 0:
        return "UNKNOWN"
    if matched == 0:
        return "ABSENT"
    if matched >= expected:
        return "OK"
    return "PARTIEL"


def build_chain(
    coverage: uefi211.Coverage,
    host: host_chain.HostScan,
) -> ChainReport:
    """Agrege firmware + host en un rapport par etape."""
    by_cat_uefi = coverage.by_category

    # Map host detections -> set par categorie
    host_by_cat: dict[str, set[str]] = {}
    for d in host.detections:
        # VPN et IDS/IPS ne protegent que s'ils tournent : un service connu
        # arrete ne compte pas (etat inconnu = running None, accepte).
        # Un lecteur d'ecran se lance a la demande : la presence suffit.
        active_required = d.category in ("vpn", "ids")
        if d.installed and not (active_required and d.running is False):
            host_by_cat.setdefault(d.category, set()).add(d.key)

    stages: list[StageReport] = []
    for stage in CHAIN_STAGES:
        cats = _STAGE_CATEGORY_MAP[stage]
        keys: list[str] = []
        for cat in cats:
            if cat in ("a11y", "vpn", "ids"):
                keys.extend(sorted(host_by_cat.get(cat, set())))
            else:
                keys.extend(sorted(by_cat_uefi.get(cat, ())))
        # expected : pour UEFI on demande au moins 1 protocole par categorie
        # mappee (sauf "uefi_firmware" qui regarde juste HII global) ; pour
        # l'host on demande au moins 1 detection par categorie.
        if stage == "uefi_firmware":
            matched = 1 if by_cat_uefi.get("hii") else 0
            expected = 1
            keys_for_status = list(by_cat_uefi.get("hii", ()))
        else:
            if stage == "os_accessibility":
                expected = 1
                matched = 1 if "a11y" in host_by_cat else 0
            elif stage == "network_security":
                expected = 1
                matched = 1 if "vpn" in host_by_cat else 0
            elif stage == "intrusion":
                expected = 1
                matched = 1 if "ids" in host_by_cat else 0
            else:
                expected = max(1, len(cats))
                matched = sum(1 for c in cats if by_cat_uefi.get(c))
            keys_for_status = keys

        stages.append(StageReport(
            stage=stage,
            label=_STAGE_LABELS[stage],
            status=_status(matched, expected),
            matched=matched,
            expected=expected,
            keys=tuple(keys_for_status),
        ))

    return ChainReport(
        firmware_bytes=coverage.bytes_total,
        firmware_sha256=coverage.sha256,
        uefi_version=coverage.uefi_version,
        host_platform=host.platform,
        stages=tuple(stages),
    )


def build_chain_from_bytes(
    firmware_bytes: bytes,
    host: host_chain.HostScan,
) -> ChainReport:
    return build_chain(uefi211.analyze(firmware_bytes), host)


def build_chain_from_paths(
    firmware_path: str,
    *,
    host_hints: Iterable[str] | None = None,
    scan_live: bool = False,
) -> ChainReport:
    """Variante pratique : prend un chemin de firmware et decide quoi faire
    pour l'hote (file_hints par defaut, scan_host si scan_live=True)."""
    coverage = uefi211.analyze_file(firmware_path)
    if scan_live:
        host = host_chain.scan_host()
    else:
        detections = host_chain.scan_file_hints(host_hints or ())
        host = host_chain.HostScan(platform="static", detections=tuple(detections))
    return build_chain(coverage, host)


__all__ = [
    "CHAIN_STAGES",
    "StageReport",
    "ChainReport",
    "build_chain",
    "build_chain_from_bytes",
    "build_chain_from_paths",
]