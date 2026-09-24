#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

PATCHES: dict[str, tuple[str, ...]] = {
    "Include/Library/EntsLib.h": (
        "#include EFI_PROTOCOL_DEFINITION (DeviceIo)",
        "extern EFI_GUID             gtEfiDeviceIoProtocolGuid;",
        "extern EFI_GUID             gtEfiUnicodeCollationProtocolGuid;",
    ),
    "Library/SctLib/Guid.c": (
        "#include EFI_PROTOCOL_DEFINITION (DeviceIo)",
        '  { &gEfiDeviceIoProtocolGuid,          L"DevIo" },',
    ),
    "Library/SctLib/SctLib.inf": (
        "  gEfiDeviceIoProtocolGuid",
    ),
    "TestCase/UEFI/EFI/Generic/EfiCompliant/BlackBoxTest/EfiCompliantBBTestPlatform_uefi.c": (
        "#include EFI_PROTOCOL_DEFINITION (Ip4Config)",
    ),
    "TestCase/UEFI/EFI/Generic/EfiCompliant/BlackBoxTest/EfiCompliantBBTest_uefi.inf": (
        "  gEfiIp4ConfigProtocolGuid",
    ),
    "TestInfrastructure/SCT/Framework/ENTS/EasLib/EntsLib.c": (
        "EFI_GUID                        gtEfiDeviceIoProtocolGuid         = EFI_DEVICE_IO_PROTOCOL_GUID;",
        "EFI_GUID                        gtEfiUnicodeCollationProtocolGuid = EFI_UNICODE_COLLATION_PROTOCOL_GUID;",
    ),
    "TestInfrastructure/SCT/Framework/ENTS/EasLib/EntsGuid.c": (
        '  { &gtEfiDeviceIoProtocolGuid, L"DevIo"},',
        '  { &gtEfiUnicodeCollationProtocolGuid, L"UnicodeCollation"},',
    ),
}


def patch_text(text: str, expected_lines: tuple[str, ...], label: str) -> str:
    lines = text.splitlines(keepends=True)
    for expected in expected_lines:
        matches = [
            index
            for index, line in enumerate(lines)
            if line.rstrip("\r\n") == expected
        ]
        if len(matches) != 1:
            raise ValueError(
                f"unexpected pinned SCT {label}: line {expected!r} "
                f"occurrence count is {len(matches)}, expected 1"
            )
        del lines[matches[0]]
    return "".join(lines)


def patch_tree(root: Path) -> None:
    for relative, expected_lines in PATCHES.items():
        path = root / relative
        if not path.is_file():
            raise ValueError(f"missing pinned SCT file: {relative}")
        with path.open("r", encoding="utf-8", newline="") as stream:
            original = stream.read()
        patched = patch_text(original, expected_lines, relative)
        with path.open("w", encoding="utf-8", newline="") as stream:
            stream.write(patched)
        with path.open("r", encoding="utf-8", newline="") as stream:
            check = stream.read()
        logical = {line.rstrip("\r\n") for line in check.splitlines(keepends=True)}
        stale = [line for line in expected_lines if line in logical]
        if stale:
            raise SystemExit(f"deprecated SCT references remain in {relative}: {stale}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sct_pkg")
    args = parser.parse_args()
    patch_tree(Path(args.sct_pkg))
    print("SCT_DEPRECATED_PROTOCOL_PATCH_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
