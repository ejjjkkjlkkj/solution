# Changelog

All notable repository changes are tracked here.

## Unreleased

### Added
- **UEFI 2.10/2.11 protocol coverage** (`omni.uefi211`): static scan of firmware binaries for HII sub-protocols, Audio Protocol (HDA / USB Audio / VoiceOutput), Virtual Keyboard, plus the network stack (HTTP/REST/TCP/UDP/DHCPv6/DNSv6). Supports UTF-16LE encoded strings. Fails closed on anything older than UEFI 2.10.
- **Host accessibility chain** (`omni.host_chain`): cross-platform scanner for installed accessibility tools (NVDA, JAWS, Narrator, Orca, VoiceOver, espeak, speech-dispatcher, brltty, pyttsx3), VPN clients (WireGuard, OpenVPN, IPsec, ZeroTier, Windows VPN), and IDS/IPS engines (Windows Defender, Suricata, Snort, Zeek, Wazuh, CrowdSec, auditd, Sysmon, ClamAV). Best-effort live `running` state detection via `tasklist` / `pgrep` / `sc query`.
- **End-to-end chain report** (`omni.end_to_end`): orchestrates firmware UEFI + host OS into a 6-step verdict (uefi_firmware, uefi_accessibility, uefi_network, os_accessibility, network_security, intrusion). Each step gets `OK` / `PARTIEL` / `ABSENT` with concrete key evidence.
- **Optional chain gates** (`omni.ceiling.CHAIN_GATE_KEYS` + `evaluate_chain`): runtime aggregation distinct from `REQUIRED_SOFTWARE_GATES`. Existing software ceiling is unchanged; the new chain gates evaluate runtime availability of accessibility / VPN / IDS tools.
- **CLI subcommands**: `uefi211-check`, `host-scan`, `chain-report`, `chain-evaluate` (multi-port intake: firmware path + host hints file or live scan).
- **Tests**: `test_uefi211.py` (10 cases), `test_host_chain.py` (7 cases), `test_end_to_end.py` (7 cases), `test_ceiling_chain.py` (6 cases). Total 30 new tests, 240/240 overall (5 pre-existing skips, 0 failures).
- **Docs**: `docs/UEFI_211_PROTOCOLS.md`, `docs/HOST_ACCESSIBILITY_CHAIN.md`, `docs/NETWORK_SECURITY.md` covering scope, guarantees, limits, JSON shape, and caveats.

- **Host hardware inventory** (`omni.host_inventory`, `omni host-inventory`): stdlib-only read of SMBIOS (BIOS, system, Type 1 UUID), registry (board, CPU, Secure Boot, HDA, keyboard) and TBS (TPM). Fail-closed identity check for the ASUS M1603QA / Ryzen 7 5800H. Attests no hardware gate. Docs: `docs/HOST_INVENTORY.md`; tests: `tests/test_host_inventory.py`.
- **Screen-reader output** (`omni.speakable`, `--format text` / `OMNI_FORMAT`): linear French reports, verdict first, one sentence per line, no decorative symbols, explicit end line. JSON stays the default. Docs: `docs/SCREEN_READER_OUTPUT.md`; tests: `tests/test_speakable.py`.
- **Read-only TPM client** (`omni.tpm_tbs`, `omni tpm-read`): pure `ctypes` TBS access for TPM 2.0 properties, random bytes and PCR 0-7. `--quote` (opt-in) adds a transient ECDSA P-256 key, a TPM2_Quote and local verification; `--attest` binds the AK to the EK and checks it against the manufacturer EK certificate. Transient objects are always flushed. Docs: `docs/TPM_READ.md`; tests: `tests/test_tpm_tbs.py`.

### Changed
- `omni.ceiling` exposes `CHAIN_GATE_KEYS` and `evaluate_chain()` for runtime evaluation. `REQUIRED_SOFTWARE_GATES` is unchanged (12 CI gates still required for `SOFTWARE_CEILING_PASS`).
- `omni.cli` adds four new subcommands plus `host-inventory`; existing commands unchanged.

### Fixed
- `end_to_end.build_chain`: a VPN or IDS/IPS detection whose service is known to be stopped no longer satisfies its stage (unknown state still counts; screen readers still count when merely installed). Stage 6 on the ASUS now rests on Windows Defender alone, since Sysmon is only present on disk.
- `host_chain` running-state detection: service names such as `WinDefend` were probed as processes and reported stopped. Hints are now probed as service and process.

### Release status
The package version remains `0.1.0`. No tagged public release has been declared yet.

## Previous entries

### Added
- Host acoustic renderer: `voice_st` binds ST (>= 0.6.0-rc.2) through its C ABI v1 behind the VoiceCore frontend and PCM gate; `omni voice-render` CLI.
- In-memory Windows audio sink (`audio_out.WaveOutSink`) and an end-to-end focus -> ST -> waveOut test with cancellation checks.
- Secret-field rules (`announce.is_secret`): values of password/PIN/credential fields are never spoken or logged.
- Screen-reader announcements: `announce.announcement` (FR/EN name/role/state/value, password values never spoken) and `SpeechController` (focus change interrupts speech).
- Exact-commit software-ceiling aggregation with fail-closed evidence handling.
- Deterministic UEFI, QEMU/OVMF, SCT, formal-proof, fuzzing, coverage, and reproducibility gates.
- Explicit hardware-only boundary and physical HIL workflow.
- SCT compatibility shim for EDK II stable 202608's non-versioned GCC toolchain profile.
- SCT compatibility shim for modern EDK II `Base.h`, backporting upstream CPU-marker detection for the pinned 202509 SCT.
- Deprecated-protocol compatibility backport for EDK II 202608, covering upstream build fix #300 and the required ENTS reference cleanup from #362.
- 0BSD licensing and public contribution metadata.

### Changed (previous)
- UEFI SCT build/runtime paths now target `RELEASE_GCC` instead of the removed `RELEASE_GCC5` profile.
- CI workflows use immutable action pins and locked external toolchain inputs.
- Pinned QEMU builds require and verify the libslirp user-network backend used by SCT runtime networking.
- Hardware-boundary aggregation now accepts exact-commit authorized `workflow_dispatch` HIL evidence while software-ceiling aggregation remains push-only.
- Final hardware-boundary enforcement now runs from completed Physical AMD HIL runs instead of taking a premature `main` push snapshot.
