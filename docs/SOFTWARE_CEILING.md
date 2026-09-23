# Software ceiling contract

A software property is not allowed to remain a hardware question if it can be reproduced in an emulator, model checker, sanitizer, fuzzer, host test or independent build runner.

## Required software evidence

- Python semantic and evidence tests
- strict native diagnostics
- ASan + UBSan
- 100% line/function/region/branch coverage for the bounded protocol core
- 100k+ coverage-guided fuzz smoke
- CBMC proof of MM and accessibility invariants
- Frama-C Eva + WP/RTE proof obligations
- GCC/Clang differential execution
- EDK II official host tests with ASan
- our EFI binary built by real EDK II
- real OVMF/QEMU execution
- deterministic QEMU record/replay
- two independent runners producing bit-identical native output
- GitHub build provenance attestation
- official UEFI SCT package built reproducibly

## Important SCT distinction

Building the official SCT is not a conformance pass. A UEFI conformance gate is PASS only after the relevant SCT suites execute against the target firmware and the results are parsed with no disallowed failures.

## Hardware-only boundary

Only after all applicable software gates are PASS may remaining failures be attributed to physical keyboard scanning, the ASUS OEM implementation, physical HDA codec/amplifier/EAPD routing, speaker acoustics, physical timing/jitter, TPM hardware behavior, or other electrical/platform-specific facts.


## Fail-closed machine gate

The machine-readable evaluator owns the required gate policy in code. Evidence
manifests use schema `omni.software-ceiling.v1` and may provide statuses and
evidence references, but they may not redefine the required gate set.

Required gate identifiers:

- `python-tests`
- `native-diagnostics`
- `asan`
- `ubsan`
- `native-coverage`
- `fuzz-100k`
- `cbmc`
- `frama-c-eva`
- `frama-c-wp`
- `compiler-differential`
- `edk2-host-tests`
- `uefi-edk2-build`
- `qemu-ovmf-execution`
- `qemu-record-replay`
- `native-reproducibility`
- `uefi-reproducibility`
- `provenance-attestation`
- `uefi-sct-build`
- `uefi-sct-execution`

A missing gate, `FAIL`, `NOT_RUN`, `SKIP`, `BLOCKED`, or an invalid
status keeps the result at `SOFTWARE_INCOMPLETE`. An empty manifest can never
pass. `uefi-sct-build` and `uefi-sct-execution` are intentionally separate:
successfully compiling the official SCT package is not execution evidence.

Example:

```json
{
  "schema": "omni.software-ceiling.v1",
  "statuses": {
    "python-tests": "PASS",
    "cbmc": "NOT_RUN"
  }
}
```

Validate with:

```text
omni ceiling-evaluate ceiling.json
```

Exit code 0 means the complete required software set passed, 1 means valid but
incomplete evidence, and 2 means the manifest itself is invalid.
