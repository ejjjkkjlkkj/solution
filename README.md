# solution — Omni Software Ceiling

Goal: push software verification until the remaining uncertainty is genuinely hardware-specific.

The repository is not a PsExec clone. It develops a cross-layer research stack for UEFI accessibility and deterministic validation: semantic firmware UI, read-only firmware modeling, tamper-evident event chains, model checking, fuzzing, replay, formal verification gates, reproducible builds and hardware-in-the-loop validation.

## Current bootstrap

```powershell
python -m pip install -e .
omni toolchain
python -m unittest discover -s tests -v
```

## Definition of done

`SOFTWARE_CEILING_PASS` is allowed only when every required software gate is `PASS`. `NOT_RUN`, `SKIP`, or missing external verification tools remain blockers. The final hardware-only gates are physical UEFI behavior, keyboard scan behavior, real HDA codec/amplifier/speaker output, physical latency/jitter, TPM quote, and OEM-specific behavior.

See `docs/ARCHITECTURE.md` and `SECURITY.md`.
