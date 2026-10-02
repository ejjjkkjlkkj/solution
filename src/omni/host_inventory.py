"""
Inventaire materiel de la machine hote, en Python pur (bibliotheque standard).

Aucun outil tiers et aucun sous-processus : les sources sont
    - la table SMBIOS brute (GetSystemFirmwareTable 'RSMB' via ctypes), la meme
      source que celle lue par OmniProbe (Type 1 : UUID systeme) ;
    - le registre Windows (winreg) : BIOS, carte mere, CPU, Secure Boot, HDA,
      peripheriques clavier ;
    - TPM Base Services (tbs.dll via ctypes) : version et interface du TPM.

Portee : cet inventaire decrit la machine. Il n'atteste AUCUN gate materiel.
Un gate (asus_oem_uefi, physical_hda_audio, ...) exige une preuve produite sur
le materiel (boot pre-OS, quote TPM, mesure acoustique) ; ``claims`` reste donc
toujours vide et ``gates_attested`` ne contient jamais de gate.

Le module est en lecture seule. Hors Windows, ``collect`` renvoie un inventaire
vide avec ``platform_supported = False`` (fail-closed pour l'identite).
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import struct
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

SCHEMA = "omni-host-inventory/1"
RSMB = 0x52534D42  # 'RSMB'
_NIL_UUIDS = {
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
}
_KEYBOARD_GUID = "{4d36e96b-e325-11ce-bfc1-08002be10318}"
_TPM_VERSIONS = {1: "1.2", 2: "2.0"}


# ---------------------------------------------------------------------------
# SMBIOS
# ---------------------------------------------------------------------------

def _strings(area: bytes) -> list[str]:
    parts = area.split(b"\x00")
    return [p.decode("ascii", "replace").strip() for p in parts if p]


def parse_smbios(raw: bytes) -> dict[str, Any]:
    """Analyse un RAW_SMBIOS_DATA (en-tete Windows de 8 octets + structures).

    Renvoie la version SMBIOS, les champs Type 0 (BIOS) et Type 1 (systeme),
    dont l'UUID. Leve ValueError sur une table tronquee ou incoherente.
    """
    if len(raw) < 8:
        raise ValueError("SMBIOS table too short")
    major, minor = raw[1], raw[2]
    length = struct.unpack_from("<I", raw, 4)[0]
    table = raw[8:8 + length]
    if len(table) != length:
        raise ValueError("SMBIOS table truncated")

    out: dict[str, Any] = {"smbios_version": f"{major}.{minor}"}
    pos = 0
    while pos + 4 <= len(table):
        stype, slen = table[pos], table[pos + 1]
        if slen < 4 or pos + slen > len(table):
            raise ValueError("malformed SMBIOS structure")
        end = table.find(b"\x00\x00", pos + slen)
        if end < 0:
            raise ValueError("unterminated SMBIOS string area")
        formatted = table[pos:pos + slen]
        strs = _strings(table[pos + slen:end + 1])

        def text(index: int) -> str | None:
            if index == 0 or index > len(strs):
                return None
            return strs[index - 1]

        if stype == 0 and slen >= 9 and "bios_vendor" not in out:
            out["bios_vendor"] = text(formatted[4])
            out["bios_version"] = text(formatted[5])
            out["bios_release_date"] = text(formatted[8])
        elif stype == 1 and slen >= 24 and "system_uuid" not in out:
            out["system_manufacturer"] = text(formatted[4])
            out["system_product"] = text(formatted[5])
            raw_uuid = bytes(formatted[8:24])
            # SMBIOS >= 2.6 : les trois premiers champs sont little-endian.
            little = (major, minor) >= (2, 6)
            value = str(uuid.UUID(bytes_le=raw_uuid) if little else uuid.UUID(bytes=raw_uuid))
            out["system_uuid"] = None if value in _NIL_UUIDS else value
        elif stype == 127:
            break
        pos = end + 2
    return out


# ---------------------------------------------------------------------------
# Sources Windows (injectables pour les tests)
# ---------------------------------------------------------------------------

def _read_smbios_windows() -> bytes | None:
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    size = kernel32.GetSystemFirmwareTable(RSMB, 0, None, 0)
    if size == 0:
        return None
    buf = ctypes.create_string_buffer(size)
    if kernel32.GetSystemFirmwareTable(RSMB, 0, buf, size) != size:
        return None
    return buf.raw


def _tpm_info_windows() -> dict[str, Any]:
    try:
        tbs = ctypes.windll.tbs  # type: ignore[attr-defined]
    except OSError:
        return {"present": False, "reason": "tbs.dll unavailable"}

    class DeviceInfo(ctypes.Structure):
        _fields_ = [
            ("structVersion", ctypes.c_uint32),
            ("tpmVersion", ctypes.c_uint32),
            ("tpmInterfaceType", ctypes.c_uint32),
            ("tpmImpRevision", ctypes.c_uint32),
        ]

    info = DeviceInfo()
    rc = tbs.Tbsi_GetDeviceInfo(ctypes.sizeof(info), ctypes.byref(info))
    if rc != 0:
        return {"present": False, "reason": f"Tbsi_GetDeviceInfo=0x{rc & 0xFFFFFFFF:08X}"}
    return {
        "present": True,
        "version": _TPM_VERSIONS.get(info.tpmVersion, f"unknown({info.tpmVersion})"),
        "interface_type": info.tpmInterfaceType,
        "impl_revision": info.tpmImpRevision,
    }


def _registry_windows() -> dict[str, Any]:
    import winreg

    def value(root: int, path: str, name: str) -> Any:
        try:
            with winreg.OpenKey(root, path) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    def subkeys(root: int, path: str) -> list[str]:
        try:
            with winreg.OpenKey(root, path) as key:
                count = winreg.QueryInfoKey(key)[0]
                return [winreg.EnumKey(key, i) for i in range(count)]
        except OSError:
            return []

    hklm = winreg.HKEY_LOCAL_MACHINE
    bios = r"HARDWARE\DESCRIPTION\System\BIOS"
    enum = r"SYSTEM\CurrentControlSet\Enum"

    hda = []
    for fn in subkeys(hklm, enum + r"\HDAUDIO"):
        for inst in subkeys(hklm, f"{enum}\\HDAUDIO\\{fn}"):
            desc = value(hklm, f"{enum}\\HDAUDIO\\{fn}\\{inst}", "DeviceDesc")
            hda.append({"id": fn, "description": str(desc).split(";")[-1] if desc else None})

    keyboards = []
    for bus in ("ACPI", "HID", "ACPI_HAL"):
        for dev in subkeys(hklm, f"{enum}\\{bus}"):
            for inst in subkeys(hklm, f"{enum}\\{bus}\\{dev}"):
                path = f"{enum}\\{bus}\\{dev}\\{inst}"
                if str(value(hklm, path, "ClassGUID")).lower() == _KEYBOARD_GUID:
                    keyboards.append({"bus": bus, "id": dev})

    return {
        "bios_vendor": value(hklm, bios, "BIOSVendor"),
        "bios_version": value(hklm, bios, "BIOSVersion"),
        "bios_release_date": value(hklm, bios, "BIOSReleaseDate"),
        "system_manufacturer": value(hklm, bios, "SystemManufacturer"),
        "system_product": value(hklm, bios, "SystemProductName"),
        "baseboard_product": value(hklm, bios, "BaseBoardProduct"),
        "cpu": (value(hklm, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString") or "").strip() or None,
        "secure_boot_enabled": (
            None
            if (v := value(hklm, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")) is None
            else bool(v)
        ),
        "hda_devices": hda,
        "keyboards": keyboards,
    }


# ---------------------------------------------------------------------------
# Inventaire
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HostInventory:
    platform_supported: bool
    firmware_mode: str  # "uefi" | "legacy" | "unknown"
    fields: dict[str, Any] = field(default_factory=dict)
    tpm: dict[str, Any] = field(default_factory=dict)
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        body = {
            "schema": SCHEMA,
            "platform_supported": self.platform_supported,
            "firmware_mode": self.firmware_mode,
            "fields": self.fields,
            "tpm": self.tpm,
            "errors": list(self.errors),
            # Ceci n'est pas une preuve de gate : voir la docstring du module.
            "gates_attested": [],
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {
            **body,
            "inventory_sha256": hashlib.sha256(canonical).hexdigest(),
            "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


def collect(
    platform: str | None = None,
    smbios_source: Callable[[], bytes | None] | None = None,
    registry_source: Callable[[], dict[str, Any]] | None = None,
    tpm_source: Callable[[], dict[str, Any]] | None = None,
) -> HostInventory:
    plat = platform if platform is not None else sys.platform
    if not plat.startswith("win"):
        return HostInventory(False, "unknown", errors=(f"unsupported platform: {plat}",))

    errors: list[str] = []
    fields: dict[str, Any] = {}

    try:
        fields.update((registry_source or _registry_windows)())
    except Exception as exc:  # lecture best-effort, jamais d'echec silencieux
        errors.append(f"registry: {exc}")

    smbios_ok = False
    try:
        raw = (smbios_source or _read_smbios_windows)()
        if raw is None:
            errors.append("smbios: table unavailable")
        else:
            # SMBIOS fait foi pour l'identite ; le registre reste en secours.
            fields.update({k: v for k, v in parse_smbios(raw).items() if v is not None})
            smbios_ok = True
    except Exception as exc:
        errors.append(f"smbios: {exc}")

    try:
        tpm = (tpm_source or _tpm_info_windows)()
    except Exception as exc:
        tpm = {"present": False, "reason": str(exc)}
        errors.append(f"tpm: {exc}")

    # Secure Boot n'existe dans le registre que sur un boot UEFI.
    mode = "uefi" if fields.get("secure_boot_enabled") is not None else ("unknown" if not smbios_ok else "legacy")
    return HostInventory(True, mode, fields, tpm, tuple(errors))


# ---------------------------------------------------------------------------
# Verification d'identite (fail-closed)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IdentityExpectation:
    system_manufacturer: str | None = None
    system_product: str | None = None
    baseboard_product: str | None = None
    cpu_contains: str | None = None
    system_uuid: str | None = None


def check_identity(inv: HostInventory, expected: IdentityExpectation) -> dict[str, Any]:
    """Compare l'inventaire a l'identite attendue. Tout ecart ou champ absent
    est un echec : on ne devine pas une identite manquante."""
    if not inv.platform_supported:
        return {"status": "FAIL", "mismatches": ["platform_unsupported"]}
    f = inv.fields
    bad: list[str] = []

    def eq(name: str, want: str | None) -> None:
        if want is None:
            return
        got = f.get(name)
        if got is None:
            bad.append(f"{name}: missing")
        elif str(got).strip().lower() != want.strip().lower():
            bad.append(f"{name}: got {got!r}, expected {want!r}")

    eq("system_manufacturer", expected.system_manufacturer)
    eq("system_product", expected.system_product)
    eq("baseboard_product", expected.baseboard_product)
    eq("system_uuid", expected.system_uuid.lower() if expected.system_uuid else None)
    if expected.cpu_contains is not None:
        cpu = f.get("cpu")
        if cpu is None:
            bad.append("cpu: missing")
        elif expected.cpu_contains.lower() not in str(cpu).lower():
            bad.append(f"cpu: {cpu!r} lacks {expected.cpu_contains!r}")
    return {"status": "PASS" if not bad else "FAIL", "mismatches": bad}


# Cible documentee dans docs/HARDWARE_HIL.md.
ASUS_M1603QA = IdentityExpectation(
    system_manufacturer="ASUSTeK COMPUTER INC.",
    baseboard_product="M1603QA",
    cpu_contains="Ryzen 7 5800H",
)
