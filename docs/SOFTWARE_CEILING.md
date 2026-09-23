# Software ceiling contract

A property is not allowed to remain a hardware question if it can be reproduced in an emulator, model checker, sanitizer, fuzzer, host test, static analyzer or independent build runner.

## Required software evidence

- semantic, IFR, SCT-summary and physical-evidence verifier tests
- strict native diagnostics plus GCC -fanalyzer and Clang static analysis
- ASan + UBSan
- 100% line/function/region/branch coverage for the bounded protocol core
- 100k+ coverage-guided fuzz smoke
- CBMC proof of MM and accessibility invariants
- Frama-C Eva + WP/RTE proof obligations
- GCC/Clang differential execution
- EDK II official host tests with ASan
- OmniProbe.efi built by pinned EDK II edk2-stable202608
- OVMF/QEMU TCG execution with fail-closed HII/evidence/final markers
- deterministic QEMU record/replay with blkreplay
- bit-identical native output from independent runners
- bit-identical OmniProbe.efi from independent runners
- GitHub/Sigstore provenance attestation plus verification
- official UEFI SCT build and runtime against pinned OVMF
- physical-media preparation and verifier logic tested without claiming physical execution

## Exact boundary

SOFTWARE_CEILING_PASS is software-only. It must not require the Physical AMD HIL workflow.
The HIL workflow is evaluated separately. Once every software gate is PASS, any remaining uncertainty is allowed to be hardware/OEM-specific rather than an unclosed software question.

## Hardware-only boundary

Only after all applicable software gates are PASS may remaining uncertainty be assigned to:

- ASUS M1603QA physical OEM UEFI execution
- real pre-OS keyboard scanning/focus timing
- physical HDA codec, amplifier/EAPD and speaker acoustics
- real interrupt/timing/jitter behavior
- TPM hardware quote/measurement behavior
- Windows/QEMU and VMware HIL evidence on the physical AMD runner
- other electrical/OEM-specific behavior

NOT_RUN, SKIP, timeout, missing marker, stale/mismatched physical challenge, missing artifact or unverified provenance must never become PASS.
