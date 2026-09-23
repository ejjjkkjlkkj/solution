#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
from dataclasses import dataclass

USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.IGNORECASE)
CONTINUE_RE = re.compile(r"^\s*continue-on-error:\s*true\s*(?:#.*)?$", re.IGNORECASE)
COMMIT_REF_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DOCKER_DIGEST_RE = re.compile(r"^docker://.+@sha256:[0-9a-fA-F]{64}$")
MUTABLE_RUNNER_RE = re.compile(r"(?:ubuntu|windows|macos)-latest", re.IGNORECASE)
PIP_COMMAND_RE = re.compile(r"^pip(?:3)?$", re.IGNORECASE)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    code: str
    value: str


def _continued_command(lines: list[str], start: int) -> str:
    """Return one shell command, including backslash-continued lines."""
    parts: list[str] = []
    cursor = start
    while True:
        part = lines[cursor].strip()
        continued = part.endswith("\\")
        if continued:
            part = part[:-1].rstrip()
        parts.append(part)
        if not continued or cursor + 1 >= len(lines):
            break
        cursor += 1
    return " ".join(parts)


def _shell_tokens(command: str) -> list[str] | None:
    try:
        return shlex.split(command, comments=True, posix=True)
    except ValueError:
        return None


def _contains_pip_install(command: str) -> bool:
    """Detect actual pip install arguments while ignoring shell comments."""
    tokens = _shell_tokens(command)
    if tokens is None:
        # A malformed command must not evade the policy.  The caller will report
        # it as an un-hashed install if the textual command contains the phrase.
        return bool(re.search(r"\bpip(?:3)?\s+install\b", command, re.IGNORECASE))
    return any(
        PIP_COMMAND_RE.fullmatch(token) and index + 1 < len(tokens)
        and tokens[index + 1].lower() == "install"
        for index, token in enumerate(tokens)
    )


def _has_require_hashes(command: str) -> bool:
    """Recognize --require-hashes as a shell argument, not as a comment."""
    tokens = _shell_tokens(command)
    return tokens is not None and "--require-hashes" in tokens


def inspect_file(path: pathlib.Path) -> list[Violation]:
    violations: list[Violation] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, raw in enumerate(lines):
        number = index + 1
        if CONTINUE_RE.match(raw):
            violations.append(Violation(str(path), number, "CONTINUE_ON_ERROR_TRUE", raw.strip()))
        if MUTABLE_RUNNER_RE.search(raw):
            violations.append(Violation(str(path), number, "MUTABLE_RUNNER_LABEL", raw.strip()))

        command = _continued_command(lines, index)
        if _contains_pip_install(command) and not _has_require_hashes(command):
            violations.append(
                Violation(str(path), number, "PIP_INSTALL_WITHOUT_HASHES", command)
            )

        match = USES_RE.match(raw)
        if not match:
            continue
        target = match.group(1)

        if target.startswith("./"):
            continue
        if target.startswith("docker://"):
            if not DOCKER_DIGEST_RE.fullmatch(target):
                violations.append(Violation(str(path), number, "DOCKER_NOT_DIGEST_PINNED", target))
            continue
        if "@" not in target:
            violations.append(Violation(str(path), number, "ACTION_REF_MISSING", target))
            continue

        action, ref = target.rsplit("@", 1)
        if "/" not in action or not COMMIT_REF_RE.fullmatch(ref):
            violations.append(Violation(str(path), number, "ACTION_NOT_COMMIT_PINNED", target))

    return violations


def inspect(root: pathlib.Path) -> list[Violation]:
    if not root.is_dir():
        raise ValueError(f"workflow directory does not exist: {root}")
    violations: list[Violation] = []
    for path in sorted(root.glob("*.y*ml")):
        violations.extend(inspect_file(path))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed GitHub Actions policy")
    parser.add_argument("root", nargs="?", default=".github/workflows", type=pathlib.Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    try:
        violations = inspect(args.root)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 2

    result = {
        "schema": "omni.workflow-policy.v1",
        "status": "PASS" if not violations else "FAIL",
        "violations": [v.__dict__ for v in violations],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if args.strict and violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
