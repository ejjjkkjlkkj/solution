# Hardware-only boundary

The project may claim **software ceiling reached** only after the final CI aggregator has accepted all required same-commit evidence.

The final verdict is content-addressed, archived and attested. Missing, pending, skipped, cancelled, timed-out or failed evidence is not PASS.

After that point, remaining uncertainty is restricted to phenomena that intrinsically require the real target:

- execution in the ASUS OEM UEFI itself;
- physical pre-OS keyboard scan/focus timing;
- the real HDA codec topology;
- amplifier/EAPD routing and the physical speaker path;
- audible speech quality, physical latency and jitter;
- a TPM quote/measurements from the actual machine;
- electrical/OEM-specific implementation behavior.

QEMU/OVMF, VMware compatibility, parsing, HII/IFR semantics, model checking, sanitizers, fuzzing, static analysis, formal proofs, SCT-on-OVMF, record/replay, reproducibility and provenance remain software obligations and are not allowed to be relabeled as hardware limitations.
