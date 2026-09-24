# Changelog

All notable repository changes are tracked here.

## Unreleased

### Added
- Exact-commit software-ceiling aggregation with fail-closed evidence handling.
- Deterministic UEFI, QEMU/OVMF, SCT, formal-proof, fuzzing, coverage, and reproducibility gates.
- Explicit hardware-only boundary and physical HIL workflow.
- SCT compatibility shim for EDK II stable 202608's non-versioned GCC toolchain profile.
- SCT compatibility shim for modern EDK II `Base.h`, backporting upstream CPU-marker detection for the pinned 202509 SCT.
- Deprecated-protocol compatibility backport for EDK II 202608, covering upstream build fix #300 and the required ENTS reference cleanup from #362.
- 0BSD licensing and public contribution metadata.

### Changed
- UEFI SCT build/runtime paths now target `RELEASE_GCC` instead of the removed `RELEASE_GCC5` profile.
- CI workflows use immutable action pins and locked external toolchain inputs.

### Release status
The package version remains `0.1.0`. No tagged public release has been declared yet.
