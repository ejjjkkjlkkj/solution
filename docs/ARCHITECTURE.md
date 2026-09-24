# Architecture

`solution` is built around five independent planes:

1. **Semantics** — firmware UI becomes a deterministic accessibility object model.
2. **Observation** — events from UEFI, MM/SMM lab, hypervisor, kernel and user mode use structured records.
3. **Evidence** — records are hash chained; artifact manifests use domain-separated Merkle leaves that bind canonical artifact path, byte length and SHA-256 content digest.
4. **Verification** — model checking, sanitizers, fuzzing, replay and differential tests close software uncertainty.
5. **Hardware-in-the-loop** — only after software gates pass do we accept physical ASUS/HDA/TPM behavior as remaining uncertainty.

The speech frontend belongs to the **Semantics** plane. Accessibility text is normalized into deterministic, renderer-neutral speech tokens before any synthesis backend is selected. The normalization contract covers French/English number expansion, firmware acronyms and clause intent while deliberately excluding formant/Klatt parameters, operating-system audio APIs and prerecorded WAV assets. This keeps HII/IFR semantics testable independently from the future natural VoiceCore renderer and provides a reference oracle for differential testing of the UEFI/C implementation.

Merkle verification treats manifests as untrusted input. Relative paths must be canonical, traversal is rejected, symlink resolution must stay inside the declared evidence root, and digest fields must be well-formed before comparison.

The project never treats SYSTEM, Ring 0, SMM or a security processor as one universal privilege hierarchy. They are separate trust domains and are modeled separately.
