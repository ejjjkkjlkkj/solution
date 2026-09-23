from __future__ import annotations

import argparse
import json

from . import ceiling, firmware, ifr


def main() -> int:
    parser = argparse.ArgumentParser(prog="omni")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("toolchain")

    fw = sub.add_parser("firmware-inspect")
    fw.add_argument("image")

    hii = sub.add_parser("ifr-inspect")
    hii.add_argument("package_list")

    ceiling_cmd = sub.add_parser("ceiling-evaluate")
    ceiling_cmd.add_argument("manifest")

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

    if args.command == "ceiling-evaluate":
        try:
            result = ceiling.evaluate_manifest(args.manifest)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(
                json.dumps(
                    {
                        "schema": ceiling.MANIFEST_SCHEMA,
                        "status": "SOFTWARE_MANIFEST_INVALID",
                        "error": str(exc),
                    },
                    indent=2,
                )
            )
            return 2
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "SOFTWARE_CEILING_PASS" else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
