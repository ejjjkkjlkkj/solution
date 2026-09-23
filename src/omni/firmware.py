from __future__ import annotations
import hashlib, pathlib, struct

FV_SIGNATURE = b"_FVH"
FV_SIGNATURE_OFFSET = 40

MARKERS = (b"AGESA", b"PSP", b"SMM", b"SecureBoot", b"AMITSESetup", b"AsusSetupIoInterface")

def _offsets(data: bytes, needle: bytes) -> list[int]:
    result: list[int] = []
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return result
        result.append(index)
        start = index + 1

def inspect(path: str | pathlib.Path) -> dict[str, object]:
    source = pathlib.Path(path)
    data = source.read_bytes()
    volumes = []
    for signature_offset in _offsets(data, FV_SIGNATURE):
        base = signature_offset - FV_SIGNATURE_OFFSET
        if base < 0 or base + 56 > len(data):
            continue
        length = struct.unpack_from("<Q", data, base + 32)[0]
        header_length = struct.unpack_from("<H", data, base + 48)[0]
        valid = length >= header_length >= 56 and base + length <= len(data)
        volumes.append({"base": base, "length": length, "header_length": header_length, "valid_bounds": valid})
    marker_map = {m.decode(): _offsets(data.lower(), m.lower()) for m in MARKERS}
    return {
        "path": str(source),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "firmware_volumes": volumes,
        "markers": {k: v for k, v in marker_map.items() if v},
        "mutation": False,
    }
