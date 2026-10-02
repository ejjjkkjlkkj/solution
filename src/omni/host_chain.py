"""
Scanner local d'accessibilite et de pile securite de l'OS hote.

Responsabilites :
    - Detecter la presence (et l'etat actif/inactif) des outils d'accessibilite
      installes sur la machine : NVDA, JAWS, Narrator, Orca, VoiceOver, espeak,
      speech-dispatcher, brltty.
    - Detecter la pile reseau de confidentialite : WireGuard, OpenVPN, IPsec
      (strongSwan / Windows IKE), ZeroTier, plus les clients VPN integres.
    - Detecter la pile IDS/IPS : Windows Defender, Suricata, Snort, Zeek,
      Wazuh / OSSEC, CrowdSec, auditd, Sysmon, Crowdsec, ClamAV.

Le module est fait pour etre appele en local uniquement. Aucun effet de bord,
aucun service n'est demarre / arrete : on regarde le disque, les binaires,
les services systeme.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Bases de detecteurs par categorie
# ---------------------------------------------------------------------------

# Accessibilite : (cle, label humain, [chemins candidats])
A11Y_DETECTORS: list[tuple[str, str, list[str]]] = [
    ("nvda",        "NVDA (Windows)",       [
        r"C:\Program Files (x86)\NVDA",
        r"C:\Program Files\NVDA",
        "/usr/share/nvda",
    ]),
    ("jaws",        "JAWS (Freedom Sci.)",  [
        r"C:\Program Files\Freedom Scientific\JAWS",
        r"C:\Program Files (x86)\Freedom Scientific\JAWS",
        r"C:\Program Files\JAWS",
    ]),
    ("narrator",    "Narrator (Windows)",   [
        r"C:\Windows\SystemApps\Microsoft.Windows.NarratorQuickStart",
    ]),
    ("orca",        "Orca (GNOME)",         [
        "/usr/bin/orca",
        "/usr/share/orca",
    ]),
    ("voiceover",   "VoiceOver (macOS)",    [
        "/System/Library/CoreServices/VoiceOver.app",
    ]),
    ("espeak",      "espeak / espeak-ng",   [
        "/usr/bin/espeak",
        "/usr/bin/espeak-ng",
    ]),
    ("speech_dispatcher", "speech-dispatcher", [
        "/usr/bin/speech-dispatcher",
    ]),
    ("brltty",      "BRLTTY (braille)",     [
        "/usr/bin/brltty",
    ]),
    ("pyttsx3",     "pyttsx3 (Python)",     []),  # binaire indirect, voir _probe_pyttsx3
]

# VPN : (cle, label humain, [chemins candidats])
VPN_DETECTORS: list[tuple[str, str, list[str]]] = [
    ("wireguard",   "WireGuard",            [
        r"C:\Program Files\WireGuard",
        "/usr/bin/wg",
        "/usr/sbin/wg",
    ]),
    ("openvpn",     "OpenVPN",              [
        r"C:\Program Files\OpenVPN",
        r"C:\Program Files\Tunnelblick",
        "/usr/sbin/openvpn",
        "/usr/bin/openvpn",
    ]),
    ("ipsec",       "IPsec (strongSwan / Windows IKE)", [
        "/usr/sbin/strongswan",
        "/usr/sbin/charon",
        r"C:\Windows\System32\ikeext.dll",
    ]),
    ("zerotier",    "ZeroTier",             [
        r"C:\ProgramData\ZeroTier",
        "/usr/bin/zerotier-one",
    ]),
    ("windows_vpn", "Windows VPN integre",  [
        r"C:\Windows\System32\raserver.exe",
        r"C:\Windows\System32\rraserver.exe",
    ]),
]

# IDS / IPS : (cle, label humain, [chemins candidats])
IDS_DETECTORS: list[tuple[str, str, list[str]]] = [
    ("windows_defender", "Windows Defender", [
        r"C:\ProgramData\Microsoft\Windows Defender\Platform",
    ]),
    ("suricata",    "Suricata",             ["/usr/bin/suricata", "/usr/sbin/suricata"]),
    ("snort",       "Snort",                ["/usr/bin/snort", "/usr/sbin/snort"]),
    ("zeek",        "Zeek",                 ["/usr/bin/zeek", "/opt/zeek/bin/zeek"]),
    ("wazuh",       "Wazuh Agent",          [
        r"C:\Program Files (x86)\ossec-agent",
        r"C:\Program Files\ossec-agent",
        "/var/ossec",
    ]),
    ("crowdsec",    "CrowdSec",             ["/usr/bin/crowdsec"]),
    ("auditd",      "auditd (Linux)",       ["/usr/sbin/auditd", "/sbin/auditd"]),
    ("sysmon",      "Sysmon (Sysinternals)", [
        r"C:\Windows\System32\drivers\sysmon.sys",
        r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates",
    ]),
    ("clamav",      "ClamAV",               ["/usr/bin/clamd", "/usr/bin/clamscan"]),
]


# ---------------------------------------------------------------------------
# Resultat
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Detection:
    key: str
    label: str
    category: str
    installed: bool
    running: bool | None
    evidence: str

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "label": self.label,
            "category": self.category,
            "installed": self.installed,
            "running": self.running,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class HostScan:
    platform: str
    detections: tuple[Detection, ...]

    def as_dict(self) -> dict[str, object]:
        out = {
            "platform": self.platform,
            "categories": {},
        }
        for d in self.detections:
            out["categories"].setdefault(d.category, []).append(d.as_dict())
        return out

    def passed(self, required_categories: tuple[str, ...] = ("a11y", "vpn", "ids")) -> bool:
        """PASS si chaque categorie requise a au moins une detection 'installed'."""
        present = {d.category for d in self.detections if d.installed}
        return all(cat in present for cat in required_categories)


# ---------------------------------------------------------------------------
# Detection par chemin
# ---------------------------------------------------------------------------

def _exists(path: str) -> bool:
    try:
        return Path(path).exists()
    except OSError:
        return False


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _probe_pyttsx3() -> bool:
    """Tente d'importer pyttsx3 (TTS offline Python)."""
    try:
        import pyttsx3  # noqa: F401
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Detection de l'etat "running" (best-effort, cross-platform)
# ---------------------------------------------------------------------------

def _service_running_win(name: str) -> bool | None:
    """Windows : demande au SCM si un service tourne."""
    if sys.platform != "win32":
        return None
    candidates = [
        name,
        f"{name}.service",
        f"{name}_svc",
    ]
    for candidate in candidates:
        try:
            out = subprocess.run(
                ["sc", "query", candidate],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0 and "RUNNING" in out.stdout.upper():
                return True
            if out.returncode == 0 and "STOPPED" in out.stdout.upper():
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return None


def _process_running(name: str) -> bool | None:
    """Multi-plateforme : cherche un processus par nom."""
    if sys.platform == "win32":
        return _process_running_win(name)
    return _process_running_posix(name)


def _process_running_win(name: str) -> bool | None:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {name}.exe"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0:
            return None
        return name.lower() in out.stdout.lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _process_running_posix(name: str) -> bool | None:
    if _which("pgrep") is not None:
        try:
            out = subprocess.run(
                ["pgrep", "-x", name], capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0:
                return True
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    if _which("ps") is not None:
        try:
            out = subprocess.run(
                ["ps", "-eo", "comm"], capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0:
                return name in out.stdout.split()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    return None


# ---------------------------------------------------------------------------
# Service name hint pour la detection "running"
# ---------------------------------------------------------------------------

_RUNNING_HINT: dict[str, tuple[str, ...]] = {
    "nvda":            ("nvda",),
    "jaws":            ("jfw",),
    "narrator":        ("narrator",),
    "wireguard":       ("wireguard",),
    "openvpn":         ("openvpn",),
    "wazuh":           ("wazuh", "ossec"),
    "sysmon":          ("Sysmon64", "Sysmon"),
    "windows_defender": ("WinDefend", "MsMpEng"),
    "suricata":        ("suricata",),
    "snort":           ("snort",),
    "zeek":            ("zeek",),
    "crowdsec":        ("crowdsec",),
    "auditd":          ("auditd",),
    "clamav":          ("clamd", "clamav"),
}


def _is_running(hints: Iterable[str]) -> bool | None:
    """Chaque indice est sonde comme service (Windows) puis comme processus.

    True des qu'une sonde repond oui ; False si au moins une sonde a repondu
    non et aucune oui ; None si aucune sonde n'a pu conclure.
    """
    answers: list[bool] = []
    for hint in hints:
        for probe in (_service_running_win, _process_running):
            answer = probe(hint)
            if answer is True:
                return True
            if answer is not None:
                answers.append(answer)
    return False if answers else None


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _scan_category(
    detectors: list[tuple[str, str, list[str]]],
    category: str,
    *,
    extra_probes: dict[str, callable] | None = None,
) -> list[Detection]:
    out: list[Detection] = []
    for key, label, candidates in detectors:
        installed = False
        evidence = ""

        if key == "pyttsx3" and extra_probes and "pyttsx3" in extra_probes:
            installed = bool(extra_probes["pyttsx3"]())
            evidence = "module pyttsx3 importable" if installed else ""
        else:
            for path in candidates:
                if _exists(path):
                    installed = True
                    evidence = path
                    break

        running = _is_running(_RUNNING_HINT.get(key, ())) if installed else None

        out.append(Detection(
            key=key,
            label=label,
            category=category,
            installed=installed,
            running=running,
            evidence=evidence,
        ))
    return out


def scan_host(
    *,
    a11y: bool = True,
    vpn: bool = True,
    ids: bool = True,
) -> HostScan:
    """Execute la strategie par categorie et agrege le resultat.

    Chaque categorie est optionnelle pour permettre des scans cibles.
    """
    detections: list[Detection] = []
    if a11y:
        detections.extend(_scan_category(A11Y_DETECTORS, "a11y",
                                         extra_probes={"pyttsx3": _probe_pyttsx3}))
    if vpn:
        detections.extend(_scan_category(VPN_DETECTORS, "vpn"))
    if ids:
        detections.extend(_scan_category(IDS_DETECTORS, "ids"))

    return HostScan(
        platform=sys.platform,
        detections=tuple(detections),
    )


def scan_file_hints(paths: Iterable[str]) -> list[Detection]:
    """Detection rapide basee uniquement sur une liste de chemins fournis.

    Utile pour les tests unitaires et pour l'integration CI : pas besoin
    de scanner la machine reelle.
    """
    detections: list[Detection] = []
    paths_set = set(paths)
    for detectors, category in (
        (A11Y_DETECTORS, "a11y"),
        (VPN_DETECTORS, "vpn"),
        (IDS_DETECTORS, "ids"),
    ):
        for key, label, candidates in detectors:
            installed = False
            evidence = ""
            for path in candidates:
                if path in paths_set or _exists(path):
                    installed = True
                    evidence = path
                    break
            if installed:
                detections.append(Detection(
                    key=key, label=label, category=category,
                    installed=True, running=None, evidence=evidence,
                ))
    return detections


__all__ = [
    "Detection",
    "HostScan",
    "A11Y_DETECTORS",
    "VPN_DETECTORS",
    "IDS_DETECTORS",
    "scan_host",
    "scan_file_hints",
]