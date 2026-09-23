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
- physical-media preparation + verifier bound to the expected EFI SHA-256 and a fresh 256-bit challenge

## Pinned supply-chain inputs

EDK II stable 202608 is pinned to commit 2970e5699ba6267f3384ffab20f96647578aebc8.
SCT runtime/build uses edk2-test-stable202509 commit 2b2a16ac239cd89d778cb79ae6e42c533fc4c25a with edk2-stable202508 commit d46aa46c8361194521391aa581593e556c707c6e.

GitHub artifact attestations are treated as SLSA v1.0 Build Level 2 evidence. This repository does not claim Build Level 3 solely from an attestation.

## SCT distinction

A successful SCT build or an SCT run against OVMF is not a conformance result for the ASUS firmware. OEM conformance exists only after the applicable SCT suites execute against that physical target and the result set is parsed under an explicit policy.

## Hardware-only boundary

Only after all applicable software gates are PASS may remaining uncertainty be assigned to:

- ASUS M1603QA physical OEM UEFI execution
- real pre-OS keyboard scanning/focus timing
- physical HDA codec, amplifier/EAPD and speaker acoustics
- real interrupt/timing/jitter behavior
- TPM hardware quote/measurement behavior
- other electrical/OEM-specific behavior

NOT_RUN, SKIP, timeout, missing marker, stale/mismatched physical challenge, missing artifact or unverified provenance must never become PASS.

## Immutable GitHub Actions

Every external GitHub Action is pinned to a 40-hex commit SHA. Local actions are allowed; Docker actions must use a SHA-256 image digest. The mandatory workflow-policy gate rejects movable tags and `continue-on-error: true`, preventing later edits from silently weakening the software ceiling.
