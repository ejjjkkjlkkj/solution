#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_NAME = "OMNI-BUNDLE-MANIFEST.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tracked_members(root: pathlib.Path) -> list[tuple[str, bytes]]:
    root = root.resolve()
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    names = [name for name in proc.stdout.decode("utf-8").split("\0") if name]
    members: list[tuple[str, bytes]] = []

    for name in sorted(names):
        rel = pathlib.PurePosixPath(name)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"unsafe tracked path: {name}")
        path = root.joinpath(*rel.parts)
        if path.is_symlink():
            raise ValueError(f"tracked symlink is not allowed in deterministic bundle: {name}")
        if not path.is_file():
            raise ValueError(f"tracked file missing from worktree: {name}")
        try:
            path.resolve().relative_to(root)
        except ValueError as exc:
            raise ValueError(f"tracked path escapes repository: {name}") from exc
        if rel.as_posix() == MANIFEST_NAME:
            raise ValueError(f"reserved bundle manifest path is tracked: {MANIFEST_NAME}")
        members.append((rel.as_posix(), path.read_bytes()))

    if not members:
        raise ValueError("repository has no tracked files")
    return members


def manifest_bytes(members: list[tuple[str, bytes]]) -> bytes:
    payload = {
        "schema": "omni.bundle-manifest.v1",
        "files": [
            {
                "path": name,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
            }
            for name, data in members
        ],
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    return info


def create_bundle(root: pathlib.Path, output: pathlib.Path) -> str:
    members = tracked_members(root)
    manifest = manifest_bytes(members)

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        allowZip64=True,
    ) as archive:
        for name, data in members:
            archive.writestr(
                zip_info(name),
                data,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
        archive.writestr(
            zip_info(MANIFEST_NAME),
            manifest,
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )

    return hashlib.sha256(output.read_bytes()).hexdigest().upper()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: deterministic_bundle.py OUTPUT.zip", file=sys.stderr)
        return 2
    try:
        digest = create_bundle(ROOT, pathlib.Path(sys.argv[1]))
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError, ValueError) as exc:
        print(f"deterministic bundle failed: {exc}", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
