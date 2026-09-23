from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import ceiling, firmware, ifr


def _load_manifest(path: Path, label: str) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise SystemExit(f"{label} manifest must be a JSON object of string statuses")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(prog="omni")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("toolchain")

    fw = sub.add_parser("firmware-inspect")
    fw.add_argument("image")

    hii = sub.add_parser("ifr-inspect")
    hii.add_argument("package_list")

    sw = sub.add_parser("software-ceiling")
    sw.add_argument("manifest", type=Path)

    hw = sub.add_parser("hardware-boundary")
    hw.add_argument("manifest", type=Path)

    args = parser.parse_args()

    if args.command == "toolchain":
        print(json.dumps(ceiling.probe(), indent=2))
        return 0
    if args.command == "firmware-inspect":
        print(json.dumps(firmware.inspect(args.image), indent=2))
        return 0
    if args.command == "ifr-inspect":
        print(json.dumps(ifr.inspect_file(args.package_list), indent=2))
        return 0
    if args.command == "software-ceiling":
        result = ceiling.evaluate(_load_manifest(args.manifest, "software ceiling"))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "SOFTWARE_CEILING_PASS" else 1
    if args.command == "hardware-boundary":
        result = ceiling.evaluate_hardware(_load_manifest(args.manifest, "hardware boundary"))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
