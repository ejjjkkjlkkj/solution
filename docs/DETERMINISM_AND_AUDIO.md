# Determinism and audio gates

Navigation is software-complete only when the semantic graph is fully reachable, actions are deterministic, password values are redacted, and every non-terminal state can return to the root.

Cross-backend traces are normalized by role/name/value/state rather than volatile IDs or timestamps. QEMU, VMware and physical traces can therefore be compared without masking meaningful differences.

The PCM gate proves signal integrity, not human intelligibility. It rejects empty, near-silent, clipped, DC-biased and structurally invalid mono PCM16 output. Intelligibility and physical speaker quality remain separate hardware-in-the-loop gates.
