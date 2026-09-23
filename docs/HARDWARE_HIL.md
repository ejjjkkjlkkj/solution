# Physical AMD hardware-in-the-loop

This workflow deliberately does not modify ASUS OEM firmware.

A hosted Linux runner builds one immutable OmniProbe.efi and three media forms:

- omni-fat.img for virtual boot
- omni-boot.vmdk for VMware Workstation
- omni-gpt.img with a GPT EFI System Partition for physical USB boot

The physical Windows self-hosted runner asserts the ASUS M1603QA / Ryzen 7 5800H identity, captures BIOS/board/Secure Boot/TPM/VBS/HDA inventory, then executes the same EFI payload under QEMU and VMware.

The UEFI payload is fail-closed. OMNI_UEFI_PASS is emitted only when:

- OMNI-CHALLENGE.TXT contains a valid 256-bit hexadecimal challenge;
- HII/IFR validation passes;
- OMNI-EVIDENCE.TXT is written and flushed successfully.

Virtual backends additionally require OMNI_CHALLENGE_PASS, OMNI_HII_PASS and OMNI_EVIDENCE_PASS.

## Final physical gate

Flash omni-gpt.img to removable media and mount it in Windows. Before reboot, verify that BOOTX64.EFI is the expected artifact and replace the CI challenge with a fresh challenge whose expected value is stored **off the boot media**:

    python tools/prepare_physical_media.py --mount D:\ --expected-sha256 <SHA256> --challenge-out C:\Temp\omni-expected-challenge.txt

The preparation tool:

- verifies EFI/BOOT/BOOTX64.EFI against the expected SHA-256;
- deletes any previous OMNI-EVIDENCE.TXT;
- generates a cryptographically random 256-bit challenge;
- writes OMNI-CHALLENGE.TXT to the boot media;
- stores the expected challenge in the requested off-media file.

Boot the USB through the real ASUS UEFI. After returning to Windows, verify the fresh evidence:

    python tools/verify_uefi_evidence.py --evidence D:\OMNI-EVIDENCE.TXT --efi D:\EFI\BOOT\BOOTX64.EFI --expected-sha256 <SHA256> --expected-challenge <64_HEX_FROM_OFF_MEDIA_FILE>

A verifier PASS rejects:

- stale evidence from a previous boot;
- a missing, malformed or mismatched challenge;
- firmware-reported HII/UEFI failure;
- malformed or incomplete HII statistics;
- a modified EFI binary.

This binds the returned evidence to the exact expected payload and to the fresh pre-boot challenge. It is still not a cryptographic remote attestation of the motherboard.

## Genuinely hardware-only remainder

After the physical evidence gate passes, software-only CI still cannot prove:

- speaker intelligibility and acoustic quality;
- physical HDA codec/amplifier/EAPD routing;
- real pre-OS keyboard behavior;
- TPM electrical/platform behavior and quotes;
- ASUS-specific firmware timing or other electrical/OEM behavior.

Those require observation on the actual machine.

## Per-run freshness binding

Virtual HIL evidence is bound to the exact Git commit. The build embeds a 64-hex challenge derived from `GITHUB_SHA` on the boot media. OmniProbe emits the exact challenge to serial/debug output and persists it in `OMNI-EVIDENCE.TXT`. The Windows QEMU and VMware jobs delete prior logs before launch and require the exact expected challenge plus all PASS markers and no FAIL markers. A stale log from another run cannot satisfy the gate.
