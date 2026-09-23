# Architecture

`solution` is built around five independent planes:

1. **Semantics** — firmware UI becomes a deterministic accessibility object model.
2. **Observation** — events from UEFI, MM/SMM lab, hypervisor, kernel and user mode use structured records.
3. **Evidence** — records are hash chained; artifact manifests use domain-separated Merkle leaves that bind canonical artifact path, byte length and SHA-256 content digest.
4. **Verification** — model checking, sanitizers, fuzzing, replay and differential tests close software uncertainty.
5. **Hardware-in-the-loop** — only after software gates pass do we accept physical ASUS/HDA/TPM behavior as remaining uncertainty.

Merkle verification treats manifests as untrusted input. Relative paths must be canonical, traversal is rejected, symlink resolution must stay inside the declared evidence root, and digest fields must be well-formed before comparison.

The project never treats SYSTEM, Ring 0, SMM or a security processor as one universal privilege hierarchy. They are separate trust domains and are modeled separately.


## Flight evidence canonicalization

Flight records use scheme `omni.flight.v1`. Event payloads must be strict JSON:
object keys are strings, numbers are finite, and unsupported runtime types are
rejected before hashing. Hashes are domain-separated and chained from the
all-zero SHA-256 genesis value.

Verification is fail-closed: malformed hashes, record shapes, event payloads,
indexes, schemes, and an empty chain all return a deterministic failure instead
of being accepted or raising through the validation boundary.
