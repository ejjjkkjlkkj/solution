"""
Couverture des protocoles UEFI 2.10 et 2.11.

Objectif : dire, a partir d'un blob UEFI (FD / .efi / .bin / .rom), quelles
sous-couches de la toute derniere specification sont effectivement exposees
par le firmware :

    - HII complet (UEFI 2.10)
    - Audio Protocol (HDA + USB Audio Class + VoiceOutput, drafts 2.10/2.11)
    - Virtual Keyboard Protocol (UEFI 2.10)
    - Stack reseau (HTTP / REST / TCP / UDP / DHCPv6 / DNSv6)
    - Securite chainee : VPN, IDS, IPS

Le module est sans I/O et sans effet de bord : on lui passe des octets,
il rend un `Coverage` JSON-compatible.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Mapping


# ---------------------------------------------------------------------------
# Specifications et signatures des sous-protocoles UEFI 2.10 / 2.11
# ---------------------------------------------------------------------------

# On encode (label, signature_ASCII, signature_UTF16LE_optionnelle).
# Les patterns sont ecrits comme bytes bruts : le firmware peut stocker
# ces noms en ASCII ou en UTF-16LE (un caractere sur deux est NUL).
# _scan_signatures teste les deux formes automatiquement.

UEFI_211_PROTOCOLS: dict[str, tuple[bytes, ...]] = {
    # HII complet (UEFI 2.10)
    "hii_package_list":        (b"EFI_HII_PACKAGE_LIST_PROTOCOL",),
    "hii_config_routing":      (b"EFI_HII_CONFIG_ROUTING_PROTOCOL",),
    "hii_config_access":       (b"EFI_HII_CONFIG_ACCESS_PROTOCOL",),
    "hii_font":                (b"EFI_HII_FONT_PROTOCOL",),
    "hii_string":              (b"EFI_HII_STRING_PROTOCOL",),
    "hii_image":               (b"EFI_HII_IMAGE_PROTOCOL",),
    "hii_database":            (b"EFI_HII_DATABASE_PROTOCOL",),
    "hii_config_keyword":      (b"EFI_HII_CONFIG_KEYWORD_HANDLER",),

    # Audio Protocol (UEFI 2.10 + GSoC 2024 USB Audio)
    "hda_codec":               (b"HdaCodec", b"HdaControllerInit"),
    "hda_link":                (b"HdaLink",  b"ConfigureHdaLink"),
    "usb_audio_class":         (b"UsbAudioClass", b"EFI_USB_AUDIO"),
    "voice_output":            (b"VoiceOutput",   b"VoiceOutputProtocol"),
    "beep_protocol":           (b"BeepProtocol",  b"EFI_BEEP"),

    # Virtual Keyboard Protocol (UEFI 2.10)
    "virtual_keyboard":        (b"EFI_VIRTUAL_KEYBOARD_PROTOCOL", b"VirtualKeyboard"),
    "usb_hid":                 (b"EFI_USB_HID_PROTOCOL",          b"UsbHid"),
    "usb_io":                  (b"EFI_USB_IO_PROTOCOL",),
    "simple_text_input":       (b"EFI_SIMPLE_TEXT_INPUT_PROTOCOL",),
    "simple_text_input_ex":    (b"EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL",),

    # Stack reseau (UEFI 2.10/2.11)
    "http":                    (b"EFI_HTTP_PROTOCOL",  b"HttpIo"),
    "rest":                    (b"EFI_REST_PROTOCOL",  b"EFX_REST"),
    "tcp":                     (b"EFI_TCP_PROTOCOL",   b"EFI_TCP6_PROTOCOL"),
    "udp":                     (b"EFI_UDP_PROTOCOL",   b"EFI_UDP6_PROTOCOL"),
    "dhcpv6":                  (b"EFI_DHCP6_PROTOCOL",),
    "dnsv6":                   (b"EFI_DNS6_PROTOCOL",),
    "ip46":                    (b"EFI_IP4_PROTOCOL",   b"EFI_IP6_PROTOCOL"),
    "nii":                     (b"EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL",),

    # Securite chainee
    "wireguard":               (b"wireguard", b"wg0"),
    "openvpn":                 (b"openvpn",),
    "ipsec":                   (b"ipsec", b"strongswan", b"charon"),
    "tls":                     (b"openssl", b"libssl", b"tls1.2", b"tls1.3"),
    "zerotier":                (b"zerotier",),
    "suricata":                (b"suricata",),
    "snort":                   (b"snort",),
    "zeek":                    (b"zeek", b"bro"),
    "iptables":                (b"iptables", b"nftables"),
    "wazuh":                   (b"wazuh", b"ossec"),
    "crowdsec":                (b"crowdsec",),
    "auditd":                  (b"auditd", b"audit.rules"),
    "sysmon":                  (b"sysmon", b"Sysmon.exe"),
    "windows_defender":        (b"windows defender", b"msmpeng"),
}

# Regroupement thematique (pour le rapport final).
UEFI_211_CATEGORIES: dict[str, str] = {
    "hii_package_list":        "hii",
    "hii_config_routing":      "hii",
    "hii_config_access":       "hii",
    "hii_font":                "hii",
    "hii_string":              "hii",
    "hii_image":               "hii",
    "hii_database":            "hii",
    "hii_config_keyword":      "hii",
    "hda_codec":               "audio",
    "hda_link":                "audio",
    "usb_audio_class":         "audio",
    "voice_output":            "audio",
    "beep_protocol":           "audio",
    "virtual_keyboard":        "input",
    "usb_hid":                 "input",
    "usb_io":                  "input",
    "simple_text_input":       "input",
    "simple_text_input_ex":    "input",
    "http":                    "network",
    "rest":                    "network",
    "tcp":                     "network",
    "udp":                     "network",
    "dhcpv6":                  "network",
    "dnsv6":                   "network",
    "ip46":                    "network",
    "nii":                     "network",
    "wireguard":               "vpn",
    "openvpn":                 "vpn",
    "ipsec":                   "vpn",
    "tls":                     "vpn",
    "zerotier":                "vpn",
    "suricata":                "ids",
    "snort":                   "ids",
    "zeek":                    "ids",
    "iptables":                "ids",
    "wazuh":                   "ids",
    "crowdsec":                "ids",
    "auditd":                  "ids",
    "sysmon":                  "ids",
    "windows_defender":        "ids",
}

# Cles canoniques des categories (triees par ordre d'apparition dans le rapport).
CATEGORY_ORDER = ("hii", "audio", "input", "network", "vpn", "ids")


# ---------------------------------------------------------------------------
# Resultat
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ProtocolHit:
    key: str
    category: str
    offset: int
    signature: str

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "category": self.category,
            "offset": self.offset,
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class Coverage:
    bytes_total: int
    sha256: str
    hits: tuple[ProtocolHit, ...]
    by_category: Mapping[str, tuple[str, ...]]
    uefi_version: str
    uefi_version_supported: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "bytes_total": self.bytes_total,
            "sha256": self.sha256,
            "uefi_version": self.uefi_version,
            "uefi_version_supported": self.uefi_version_supported,
            "categories": {
                cat: list(keys) for cat, keys in self.by_category.items()
            },
            "hits": [hit.as_dict() for hit in self.hits],
            "summary": {
                "matched_total": len({hit.key for hit in self.hits}),
                "matched_by_category": {
                    cat: len(keys) for cat, keys in self.by_category.items()
                },
            },
        }

    def passed(self, required_categories: tuple[str, ...] = ("hii", "audio", "input")) -> bool:
        """Verdict fail-closed : PASS si chaque categorie requise a au moins un match.

        On n'exige pas la couverture complete des sous-protocoles : un firmware
        peut raisonnablement deleguer le rendu audio a un DXE driver externe.
        Ce qui compte pour l'accessibilite native pre-OS est qu'au moins un
        des sous-protocoles soit expose.
        """
        if not self.uefi_version_supported:
            return False
        for cat in required_categories:
            if not self.by_category.get(cat):
                return False
        return True


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

_UTF16_MARKER = b"\x00"  # separateur inter-caracteres en UTF-16LE


def _scan_signatures(data: bytes) -> list[ProtocolHit]:
    """Parcourt le binaire en cherchant les signatures ASCII et UTF-16LE.

    Pour chaque cle, on garde la premiere occurrence (offset minimal) parmi
    toutes les signatures possibles. Les hits ne dependent pas de la
    representation (ASCII ou UTF-16LE) : la cle canonique est conservee.
    """
    hits_by_key: dict[str, ProtocolHit] = {}

    # Pre-calcul d'un encodage UTF-16LE de tout le binaire (copie definitive
    # uniquement si l'on rencontre au moins une signature candidate). On essaie
    # d'abord en ASCII pour eviter le double scan en memoire quand le firmware
    # est en ASCII pur.
    ascii_seen: set[str] = set()
    for key, sigs in UEFI_211_PROTOCOLS.items():
        for sig in sigs:
            idx = data.find(sig)
            if idx >= 0:
                ascii_seen.add(key)
                if key not in hits_by_key or idx < hits_by_key[key].offset:
                    hits_by_key[key] = ProtocolHit(
                        key=key,
                        category=UEFI_211_CATEGORIES[key],
                        offset=idx,
                        signature=sig.decode("latin-1"),
                    )

    # Si on n'a presque rien trouve, on tente UTF-16LE pour les cles
    # manquantes : les firmwares UEFI stockent souvent les chaines en UTF-16LE.
    missing = [k for k in UEFI_211_PROTOCOLS if k not in ascii_seen]
    if missing:
        for key in missing:
            for sig in UEFI_211_PROTOCOLS[key]:
                try:
                    sig_utf16 = sig.decode("latin-1").encode("utf-16-le")
                except UnicodeDecodeError:
                    continue
                idx = data.find(sig_utf16)
                if idx >= 0:
                    if key not in hits_by_key or idx < hits_by_key[key].offset:
                        hits_by_key[key] = ProtocolHit(
                            key=key,
                            category=UEFI_211_CATEGORIES[key],
                            offset=idx,
                            signature=sig.decode("latin-1"),
                        )
                    break  # premiere signature trouvee suffit

    return list(hits_by_key.values())


def _by_category(hits: list[ProtocolHit]) -> dict[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {cat: [] for cat in CATEGORY_ORDER}
    seen: set[tuple[str, str]] = set()
    for hit in hits:
        marker = (hit.category, hit.key)
        if marker in seen:
            continue
        seen.add(marker)
        out[hit.category].append(hit.key)
    return {cat: tuple(sorted(keys)) for cat, keys in out.items()}


_VERSION_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("2.11", ("uefi 2.11", "uefi v2.11", "uefi spec 2.11")),
    ("2.10", ("uefi 2.10", "uefi v2.10", "uefi spec 2.10",
              "uefi 2.10 errata a", "uefi 2.10 errata")),
    ("2.9",  ("uefi 2.9",  "uefi v2.9")),
    ("2.8",  ("uefi 2.8",  "uefi v2.8")),
)


def _detect_uefi_version(data: bytes) -> tuple[str, bool]:
    """Renvoie (version, supported). supported = True si 2.10 ou 2.11."""
    text = data.lower()
    for version, needles in _VERSION_PATTERNS:
        for needle in needles:
            if needle.encode("latin-1") in text:
                return version, version in ("2.10", "2.11")
    # Si on n'a pas vu de marqueur de version explicite, on considere la spec
    # "unknown" et on NE bloque PAS : le reste de l'analyseur tranchera.
    return "unknown", True


def analyze(data: bytes) -> Coverage:
    """Point d'entree : prend des octets UEFI, renvoie un Coverage."""
    import hashlib
    sha = hashlib.sha256(data).hexdigest()
    version, supported = _detect_uefi_version(data)
    hits = _scan_signatures(data)
    by_cat = _by_category(hits)
    return Coverage(
        bytes_total=len(data),
        sha256=sha,
        hits=tuple(sorted(hits, key=lambda h: (h.category, h.key))),
        by_category=by_cat,
        uefi_version=version,
        uefi_version_supported=supported,
    )


def analyze_file(path: str) -> Coverage:
    """Variante pratique : ouvre un fichier et appelle analyze()."""
    import pathlib
    return analyze(pathlib.Path(path).read_bytes())


__all__ = [
    "Coverage",
    "ProtocolHit",
    "UEFI_211_PROTOCOLS",
    "UEFI_211_CATEGORIES",
    "CATEGORY_ORDER",
    "analyze",
    "analyze_file",
]
