# Security policy

The project is for development and validation on systems we control.

Production-host code must not expose arbitrary kernel/physical-memory read-write, token theft, unsigned-driver loading, Secure Boot bypass, OEM SMM injection, SPI-flash override, or PSP takeover primitives.

Deep firmware work belongs in our own OVMF/EDK II/QEMU lab. Physical OEM firmware is read/measure/validate by default.
