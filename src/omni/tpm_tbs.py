"""
Client TPM 2.0 en lecture seule, en Python pur, via TPM Base Services (tbs.dll).

Commandes emises (aucune ne modifie l'etat du TPM, aucune ne cree de cle) :
    - TPM2_GetCapability (proprietes fixes : fabricant, version du firmware)
    - TPM2_GetRandom
    - TPM2_PCR_Read (banque SHA-256)

Limite : ce module ne produit PAS de quote. TPM2_Quote exige une cle de
signature (creation d'une cle sous une hierarchie, donc une ecriture dans le
TPM) ; le gate tpm_quote reste donc non atteste. ``read_pcrs`` fournit
seulement les valeurs de PCR brutes et leur condensat.

Le transport est injectable : ``transport(command: bytes) -> bytes``.
"""

from __future__ import annotations

import ctypes
import hashlib
import struct
import sys
from typing import Callable

Transport = Callable[[bytes], bytes]

TPM_ST_NO_SESSIONS = 0x8001
TPM_CC_GET_CAPABILITY = 0x0000017A
TPM_CC_GET_RANDOM = 0x0000017B
TPM_CC_PCR_READ = 0x0000017E
TPM_CAP_TPM_PROPERTIES = 6
TPM_ALG_SHA256 = 0x000B
TPM_PT_MANUFACTURER = 0x105
TPM_PT_FIRMWARE_VERSION_1 = 0x10B
TPM_PT_FIRMWARE_VERSION_2 = 0x10C
MAX_PCR_BANK = 24


class TpmError(RuntimeError):
    pass


def _command(code: int, params: bytes = b"") -> bytes:
    return struct.pack(">HII", TPM_ST_NO_SESSIONS, 10 + len(params), code) + params


def _check(resp: bytes) -> bytes:
    """Valide l'en-tete de reponse et renvoie le corps."""
    if len(resp) < 10:
        raise TpmError("response too short")
    _tag, size, rc = struct.unpack_from(">HII", resp, 0)
    if size != len(resp):
        raise TpmError(f"response size mismatch: header {size}, actual {len(resp)}")
    if rc != 0:
        raise TpmError(f"TPM response code 0x{rc:08X}")
    return resp[10:]


def _need(body: bytes, pos: int, n: int) -> None:
    if pos + n > len(body):
        raise TpmError("truncated TPM response")


def get_random(transport: Transport, count: int = 32) -> bytes:
    if not 1 <= count <= 48:
        raise ValueError("count must be between 1 and 48")
    body = _check(transport(_command(TPM_CC_GET_RANDOM, struct.pack(">H", count))))
    _need(body, 0, 2)
    (n,) = struct.unpack_from(">H", body, 0)
    _need(body, 2, n)
    if n == 0:
        raise TpmError("TPM returned no random bytes")
    return body[2:2 + n]


def fixed_properties(transport: Transport) -> dict[int, int]:
    params = struct.pack(">III", TPM_CAP_TPM_PROPERTIES, 0x100, 64)
    body = _check(transport(_command(TPM_CC_GET_CAPABILITY, params)))
    _need(body, 0, 9)
    capability, count = struct.unpack_from(">II", body, 1)
    if capability != TPM_CAP_TPM_PROPERTIES:
        raise TpmError("unexpected capability type")
    _need(body, 9, 8 * count)
    return dict(struct.unpack_from(">II", body, 9 + 8 * i) for i in range(count))


def identity(transport: Transport) -> dict[str, object]:
    props = fixed_properties(transport)
    manu = props.get(TPM_PT_MANUFACTURER)
    major, minor = props.get(TPM_PT_FIRMWARE_VERSION_1), props.get(TPM_PT_FIRMWARE_VERSION_2)
    return {
        "manufacturer": None if manu is None else struct.pack(">I", manu).decode("ascii", "replace").strip("\x00 "),
        "firmware_version": None if major is None or minor is None else f"{major:08x}.{minor:08x}",
    }


def read_pcrs(transport: Transport, indices: tuple[int, ...] = tuple(range(8))) -> dict[int, str]:
    """Lit des PCR de la banque SHA-256 (maximum 8 par commande, indices 0 a 23)."""
    if not indices or len(set(indices)) != len(indices) or any(not 0 <= i < MAX_PCR_BANK for i in indices):
        raise ValueError("indices must be unique PCR numbers between 0 and 23")
    if len(indices) > 8:
        raise ValueError("at most 8 PCRs per read")
    bitmap = bytearray(3)
    for i in indices:
        bitmap[i // 8] |= 1 << (i % 8)
    params = struct.pack(">IHB", 1, TPM_ALG_SHA256, 3) + bytes(bitmap)
    body = _check(transport(_command(TPM_CC_PCR_READ, params)))

    pos = 4  # pcrUpdateCounter
    _need(body, pos, 4)
    (sel_count,) = struct.unpack_from(">I", body, pos)
    pos += 4
    selected: list[int] = []
    for _ in range(sel_count):
        _need(body, pos, 3)
        _alg, size = struct.unpack_from(">HB", body, pos)
        pos += 3
        _need(body, pos, size)
        bits = body[pos:pos + size]
        pos += size
        selected = [b * 8 + k for b in range(size) for k in range(8) if bits[b] >> k & 1]
    _need(body, pos, 4)
    (digest_count,) = struct.unpack_from(">I", body, pos)
    pos += 4
    out: dict[int, str] = {}
    if digest_count != len(selected):
        raise TpmError("digest count does not match returned selection")
    for index in selected:
        _need(body, pos, 2)
        (n,) = struct.unpack_from(">H", body, pos)
        pos += 2
        _need(body, pos, n)
        if n != 32:
            raise TpmError("unexpected SHA-256 digest size")
        out[index] = body[pos:pos + n].hex()
        pos += n
    missing = set(indices) - out.keys()
    if missing:
        raise TpmError(f"PCRs not returned: {sorted(missing)}")
    return out


def pcr_composite(pcrs: dict[int, str]) -> str:
    """SHA-256 sur les valeurs de PCR triees par numero (condensat de lecture)."""
    return hashlib.sha256(b"".join(bytes.fromhex(pcrs[i]) for i in sorted(pcrs))).hexdigest()


def windows_transport() -> tuple[Transport, Callable[[], None]]:
    """Ouvre un contexte TBS TPM 2.0 ; renvoie (transport, close)."""
    if not sys.platform.startswith("win"):
        raise TpmError("TBS is only available on Windows")
    tbs = ctypes.windll.tbs  # type: ignore[attr-defined]

    class Params2(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("flags", ctypes.c_uint32)]

    params = Params2(2, 1 << 2)  # TBS_CONTEXT_VERSION_TWO, includeTpm20
    handle = ctypes.c_void_p()
    rc = tbs.Tbsi_Context_Create(ctypes.byref(params), ctypes.byref(handle))
    if rc != 0:
        raise TpmError(f"Tbsi_Context_Create=0x{rc & 0xFFFFFFFF:08X}")

    def submit(command: bytes) -> bytes:
        out = ctypes.create_string_buffer(4096)
        out_len = ctypes.c_uint32(len(out))
        rc = tbs.Tbsip_Submit_Command(handle, 0, 200, command, len(command), out, ctypes.byref(out_len))
        if rc != 0:
            raise TpmError(f"Tbsip_Submit_Command=0x{rc & 0xFFFFFFFF:08X}")
        return out.raw[:out_len.value]

    def close() -> None:
        tbs.Tbsip_Context_Close(handle)

    return submit, close
