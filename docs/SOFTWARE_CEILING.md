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
