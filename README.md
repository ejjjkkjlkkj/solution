# solution — Omni Software Ceiling

Goal: push software verification until the remaining uncertainty is genuinely hardware-specific.

The repository is not a PsExec clone. It develops a cross-layer research stack for UEFI accessibility and deterministic validation: semantic firmware UI, read-only firmware modeling, tamper-evident event chains, model checking, fuzzing, replay, formal verification gates, reproducible builds and hardware-in-the-loop validation.

## Current bootstrap

Run directly from the source tree; no editable install is required.

```powershell
$env:PYTHONPATH = "src"
python -m omni.cli toolchain
python -m unittest discover -s tests -v
```

```bash
export PYTHONPATH=src
python -m omni.cli toolchain
python -m unittest discover -s tests -v
```

## Definition of done

`SOFTWARE_CEILING_PASS` is allowed only when every required software gate is `PASS`. `NOT_RUN`, `SKIP`, or missing external verification tools remain blockers. The final hardware-only gates are physical UEFI behavior, keyboard scan behavior, real HDA codec/amplifier/speaker output, physical latency/jitter, TPM quote, and OEM-specific behavior.

See `docs/ARCHITECTURE.md` and `SECURITY.md`.

## Verification boundary

The exact-commit software verdict includes deterministic IFR mutation fuzzing and CI workflow/toolchain linting. The virtual UEFI proof fixes a QEMU SMBIOS Type 1 UUID and requires OmniProbe to report the same UUID; physical ASUS identity remains a separate HIL obligation.

See `docs/HARDWARE_ONLY_BOUNDARY.md` for the strict separation between software evidence and physical-only evidence.

## License

This repository is licensed under the Zero-Clause BSD license (`0BSD`). It permits use, copying, modification, and distribution for any purpose without an attribution requirement. See `LICENSE`.
