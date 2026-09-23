#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

WORKFLOW_TO_GATES = {
    "Software Ceiling": ("core_semantics", "physical_evidence_verifier"),
    "Native Verification": ("native_verification",),
    "Deep Software Ceiling": ("deep_software_verification",),
    "Deep Software Gates": ("deep_regression_gates",),
    "Independent Software Ceiling Verification": ("independent_verification",),
    "Formal Semantic Proof": ("formal_semantic_proof",),
    "Reproducibility and Provenance": ("reproducibility_and_provenance",),
    "UEFI SCT Build": ("uefi_sct_build",),
    "UEFI SCT Runtime": ("uefi_sct_runtime_ovmf",),
}

WORKFLOW_PATHS = {
    "Software Ceiling": ".github/workflows/software-ceiling.yml",
    "Native Verification": ".github/workflows/native-verification.yml",
    "Deep Software Ceiling": ".github/workflows/deep-software-ceiling.yml",
    "Deep Software Gates": ".github/workflows/deep-software-gates.yml",
    "Independent Software Ceiling Verification": ".github/workflows/independent-verification.yml",
    "Formal Semantic Proof": ".github/workflows/formal-semantic-proof.yml",
    "Reproducibility and Provenance": ".github/workflows/reproducibility.yml",
    "UEFI SCT Build": ".github/workflows/uefi-sct-build.yml",
    "UEFI SCT Runtime": ".github/workflows/uefi-sct-runtime.yml",
}

HARDWARE_WORKFLOW_TO_GATES = {
    "Physical AMD HIL": ("windows_qemu_hil", "windows_vmware_hil"),
}

HARDWARE_WORKFLOW_PATHS = {
    "Physical AMD HIL": ".github/workflows/hardware-hil.yml",
}


def _latest_run(
    runs: list[dict[str, Any]],
    name: str,
    head_sha: str,
    expected_path: str,
) -> dict[str, Any] | None:
    candidates = [
        run
        for run in runs
        if run.get("name") == name
        and run.get("path") == expected_path
        and run.get("head_sha") == head_sha
        and run.get("event") == "push"
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda run: (
            int(run.get("run_number") or 0),
            str(run.get("created_at") or ""),
        ),
    )


def build_for_mapping(
    runs_payload: dict[str, Any],
    head_sha: str,
    mapping: dict[str, tuple[str, ...]],
    paths: dict[str, str],
) -> tuple[dict[str, str], dict[str, Any]]:
    if set(mapping) != set(paths):
        raise ValueError("workflow gate/path policy mismatch")

    runs = list(runs_payload.get("workflow_runs") or [])
    manifest: dict[str, str] = {}
    details: dict[str, Any] = {"head_sha": head_sha, "workflows": {}, "ready": True}

    for workflow, gates in mapping.items():
        expected_path = paths[workflow]
        run = _latest_run(runs, workflow, head_sha, expected_path)
        if run is None:
            status = "MISSING"
            details["ready"] = False
            details["workflows"][workflow] = {
                "status": "missing",
                "conclusion": None,
                "expected_path": expected_path,
            }
        else:
            run_status = str(run.get("status") or "unknown")
            conclusion = run.get("conclusion")
            if run_status != "completed":
                status = "NOT_RUN"
                details["ready"] = False
            elif conclusion == "success":
                status = "PASS"
            else:
                status = str(conclusion or "FAIL").upper()

            details["workflows"][workflow] = {
                "id": run.get("id"),
                "run_number": run.get("run_number"),
                "status": run_status,
                "conclusion": conclusion,
                "path": run.get("path"),
                "expected_path": expected_path,
                "url": run.get("html_url"),
            }

        for gate in gates:
            manifest[gate] = status

    return manifest, details


def build(
    runs_payload: dict[str, Any],
    head_sha: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    return build_for_mapping(runs_payload, head_sha, WORKFLOW_TO_GATES, WORKFLOW_PATHS)


def build_hardware(
    runs_payload: dict[str, Any],
    head_sha: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    return build_for_mapping(
        runs_payload,
        head_sha,
        HARDWARE_WORKFLOW_TO_GATES,
        HARDWARE_WORKFLOW_PATHS,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("runs_json", type=Path)
    ap.add_argument("--head-sha", required=True)
    ap.add_argument("--manifest-out", type=Path, required=True)
    ap.add_argument("--details-out", type=Path, required=True)
    ns = ap.parse_args()

    payload = json.loads(ns.runs_json.read_text(encoding="utf-8"))
    manifest, details = build(payload, ns.head_sha)
    ns.manifest_out.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ns.details_out.write_text(
        json.dumps(details, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"manifest": manifest, "details": details}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
