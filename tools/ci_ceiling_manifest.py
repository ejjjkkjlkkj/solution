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
    "Reproducibility and Provenance": ("reproducibility_and_provenance",),
    "UEFI SCT Build": ("uefi_sct_build",),
    "UEFI SCT Runtime": ("uefi_sct_runtime_ovmf",),
    "Physical AMD HIL": ("windows_qemu_hil", "windows_vmware_hil"),
}


def _latest_run(runs: list[dict[str, Any]], name: str, head_sha: str) -> dict[str, Any] | None:
    candidates = [
        run
        for run in runs
        if run.get("name") == name
        and run.get("head_sha") == head_sha
        and run.get("event") == "push"
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda run: (int(run.get("run_number") or 0), str(run.get("created_at") or "")))


def build(runs_payload: dict[str, Any], head_sha: str) -> tuple[dict[str, str], dict[str, Any]]:
    runs = list(runs_payload.get("workflow_runs") or [])
    manifest: dict[str, str] = {}
    details: dict[str, Any] = {"head_sha": head_sha, "workflows": {}, "ready": True}

    for workflow, gates in WORKFLOW_TO_GATES.items():
        run = _latest_run(runs, workflow, head_sha)
        if run is None:
            status = "MISSING"
            details["ready"] = False
            details["workflows"][workflow] = {"status": "missing", "conclusion": None}
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
                "url": run.get("html_url"),
            }
        for gate in gates:
            manifest[gate] = status

    return manifest, details


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("runs_json", type=Path)
    ap.add_argument("--head-sha", required=True)
    ap.add_argument("--manifest-out", type=Path, required=True)
    ap.add_argument("--details-out", type=Path, required=True)
    ns = ap.parse_args()

    payload = json.loads(ns.runs_json.read_text(encoding="utf-8"))
    manifest, details = build(payload, ns.head_sha)
    ns.manifest_out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ns.details_out.write_text(json.dumps(details, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": manifest, "details": details}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
