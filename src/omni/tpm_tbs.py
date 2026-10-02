"""
Client TPM 2.0 en lecture seule, en Python pur, via TPM Base Services (tbs.dll).

Commandes emises (aucune ne modifie l'etat du TPM, aucune ne cree de cle) :
    - TPM2_GetCapability (proprietes fixes : fabricant, version du firmware)
    - TPM2_GetRandom
    - TPM2_PCR_Read (banque SHA-256)

`make_quote` (opt-in, `tpm-read --quote`) cree une cle ECDSA P-256 TRANSITOIRE
sous la hierarchie owner, signe un quote, la vidange (FlushContext) puis verifie
localement signature, nonce et condensat de PCR. Rien n'est persiste. Sans AK
certifiee, le quote prouve la coherence de la lecture, pas l'identite de la
plate-forme.

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


TPM_ST_SESSIONS = 0x8002
TPM_CC_CREATE_PRIMARY = 0x00000131
TPM_CC_QUOTE = 0x00000158
TPM_CC_FLUSH_CONTEXT = 0x00000165
TPM_RH_OWNER = 0x40000001
TPM_RS_PW = 0x40000009
TPM_ALG_ECC = 0x0023
TPM_ALG_NULL = 0x0010
TPM_ALG_ECDSA = 0x0018
TPM_ECC_NIST_P256 = 0x0003
TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018

# Courbe NIST P-256 (verification ECDSA en Python pur)
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + _A) * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return x, (lam * (p[0] - x) - p[1]) % _P


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def ecdsa_verify(pub: tuple[int, int], digest: bytes, r: int, s: int) -> bool:
    x, y = pub
    if (y * y - (x * x * x + _A * x + _B)) % _P != 0 or not (0 < r < _N and 0 < s < _N):
        return False
    z = int.from_bytes(digest, "big")
    w = pow(s, -1, _N)
    pt = _add(_mul(z * w % _N, _G), _mul(r * w % _N, (x, y)))
    return pt is not None and pt[0] % _N == r


def _b2(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def _auth_command(code: int, handles: bytes, params: bytes) -> bytes:
    auth = struct.pack(">IHBH", TPM_RS_PW, 0, 0, 0)  # session mot de passe, auth vide
    body = handles + struct.pack(">I", len(auth)) + auth + params
    return struct.pack(">HII", TPM_ST_SESSIONS, 10 + len(body), code) + body


def _ecc_signing_template() -> bytes:
    attrs = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 16) | (1 << 18)
    public = (struct.pack(">HHI", TPM_ALG_ECC, TPM_ALG_SHA256, attrs) + _b2(b"")
              + struct.pack(">H", TPM_ALG_NULL)                      # symetrique
              + struct.pack(">HH", TPM_ALG_ECDSA, TPM_ALG_SHA256)    # schema
              + struct.pack(">HH", TPM_ECC_NIST_P256, TPM_ALG_NULL)  # courbe, kdf
              + _b2(b"") + _b2(b""))                                 # unique
    return _b2(_b2(b"") + _b2(b"")) + _b2(public) + _b2(b"") + struct.pack(">I", 0)


def create_signing_key(transport: Transport, hierarchy: int = TPM_RH_OWNER) -> tuple[int, tuple[int, int]]:
    """Cree une cle ECDSA P-256 TRANSITOIRE (non persistante) ; renvoie (handle, (x, y))."""
    resp = _check(transport(_auth_command(TPM_CC_CREATE_PRIMARY, struct.pack(">I", hierarchy),
                                          _ecc_signing_template())))
    _need(resp, 0, 10)
    handle, _psize, pub_size = struct.unpack_from(">IIH", resp, 0)
    _need(resp, 10, pub_size)
    pub = resp[10:10 + pub_size]
    try:
        p = 8
        (n,) = struct.unpack_from(">H", pub, p)
        p += 2 + n + 2 + 4 + 4  # authPolicy, symetrique, schema+hash, courbe+kdf
        (xl,) = struct.unpack_from(">H", pub, p)
        x = int.from_bytes(pub[p + 2:p + 2 + xl], "big")
        p += 2 + xl
        (yl,) = struct.unpack_from(">H", pub, p)
        y = int.from_bytes(pub[p + 2:p + 2 + yl], "big")
    except struct.error as exc:
        raise TpmError("truncated public area") from exc
    return handle, (x, y)


def flush_context(transport: Transport, handle: int) -> None:
    _check(transport(_command(TPM_CC_FLUSH_CONTEXT, struct.pack(">I", handle))))


def quote(transport: Transport, handle: int, nonce: bytes, indices: tuple[int, ...]) -> dict:
    if not 1 <= len(nonce) <= 32:
        raise ValueError("nonce must be 1 to 32 bytes")
    bitmap = bytearray(3)
    for i in indices:
        bitmap[i // 8] |= 1 << (i % 8)
    params = (_b2(nonce) + struct.pack(">HH", TPM_ALG_ECDSA, TPM_ALG_SHA256)
              + struct.pack(">IHB", 1, TPM_ALG_SHA256, 3) + bytes(bitmap))
    resp = _check(transport(_auth_command(TPM_CC_QUOTE, struct.pack(">I", handle), params)))
    _need(resp, 0, 6)
    pos = 4  # parameterSize
    (alen,) = struct.unpack_from(">H", resp, pos)
    pos += 2
    _need(resp, pos, alen + 4)
    attest = resp[pos:pos + alen]
    pos += alen
    sig_alg, _hash = struct.unpack_from(">HH", resp, pos)
    pos += 4
    if sig_alg != TPM_ALG_ECDSA:
        raise TpmError("unexpected signature algorithm")
    vals = []
    for _ in range(2):
        _need(resp, pos, 2)
        (n,) = struct.unpack_from(">H", resp, pos)
        _need(resp, pos + 2, n)
        vals.append(int.from_bytes(resp[pos + 2:pos + 2 + n], "big"))
        pos += 2 + n
    return {"attest": attest, "r": vals[0], "s": vals[1]}


def verify_quote(q: dict, pub: tuple[int, int], nonce: bytes, pcrs: dict[int, str]) -> dict:
    """Verifie signature, type, nonce et condensat de PCR d'un quote ; renvoie les verdicts."""
    attest = q["attest"]
    out = {"signature_valid": ecdsa_verify(pub, hashlib.sha256(attest).digest(), q["r"], q["s"]),
           "magic_valid": False, "type_quote": False, "nonce_match": False, "pcr_digest_match": False}
    try:
        magic, qtype = struct.unpack_from(">IH", attest, 0)
        out["magic_valid"], out["type_quote"] = magic == TPM_GENERATED_VALUE, qtype == TPM_ST_ATTEST_QUOTE
        pos = 6
        (n,) = struct.unpack_from(">H", attest, pos)
        pos += 2 + n
        (n,) = struct.unpack_from(">H", attest, pos)
        out["nonce_match"] = attest[pos + 2:pos + 2 + n] == nonce
        pos += 2 + n + 8 + 4 + 4 + 1 + 8  # horloge, reset, restart, safe, firmware
        (cnt,) = struct.unpack_from(">I", attest, pos)
        pos += 4
        for _ in range(cnt):
            (size,) = struct.unpack_from(">B", attest, pos + 2)
            pos += 3 + size
        (n,) = struct.unpack_from(">H", attest, pos)
        out["pcr_digest_match"] = attest[pos + 2:pos + 2 + n].hex() == pcr_composite(pcrs)
    except struct.error:
        pass
    out["valid"] = all(out.values())
    return out


def make_quote(transport: Transport, indices: tuple[int, ...] = tuple(range(8)), hierarchy: int = TPM_RH_OWNER) -> dict:
    """Quote complet avec cle transitoire, toujours vidangee ; verifie la signature localement."""
    nonce = get_random(transport, 32)
    handle, pub = create_signing_key(transport, hierarchy)
    try:
        before = read_pcrs(transport, indices)
        q = quote(transport, handle, nonce, indices)
        after = read_pcrs(transport, indices)
    finally:
        flush_context(transport, handle)
    verdict = verify_quote(q, pub, nonce, before)
    verdict["pcrs_stable"] = before == after
    verdict["valid"] = bool(verdict["valid"] and verdict["pcrs_stable"])
    return {"nonce": nonce.hex(), "public_key": {"x": f"{pub[0]:064x}", "y": f"{pub[1]:064x}"},
            "attest": q["attest"].hex(), "signature": {"r": f"{q['r']:064x}", "s": f"{q['s']:064x}"},
            "verification": verdict, "key_flushed": True}


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
