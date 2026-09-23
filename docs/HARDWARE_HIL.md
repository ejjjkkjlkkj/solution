# Physical AMD hardware-in-the-loop

This workflow deliberately does not modify ASUS OEM firmware.

A hosted Linux runner builds one immutable OmniProbe.efi and three media forms:

- omni-fat.img for virtual boot
- omni-boot.vmdk for VMware Workstation
- omni-gpt.img with a GPT EFI System Partition for physical USB boot

The physical Windows self-hosted runner asserts the ASUS M1603QA / Ryzen 7 5800H identity, captures BIOS/board/Secure Boot/TPM/VBS/HDA inventory, then executes the same EFI payload under QEMU and VMware.

The UEFI payload is fail-closed: OMNI_UEFI_PASS is emitted only after HII validation succeeds and OMNI-EVIDENCE.TXT has been flushed. Virtual backends also require OMNI_HII_PASS and OMNI_EVIDENCE_PASS.

## Final physical gate

Flash omni-gpt.img to removable media, boot it through the real ASUS UEFI, return to the OS and retrieve:

- EFI/BOOT/BOOTX64.EFI
- OMNI-EVIDENCE.TXT

Then verify the returned evidence against the SHA-256 of OmniProbe.efi from the same workflow artifact:

    python tools/verify_uefi_evidence.py --evidence D:\\OMNI-EVIDENCE.TXT --efi D:\\EFI\\BOOT\\BOOTX64.EFI --expected-sha256 <SHA256>

A verifier PASS rejects firmware-reported failure, malformed/missing HII statistics, stale/incomplete marker sets and a modified EFI binary. It binds the returned evidence to media containing the expected payload; it is not a cryptographic remote attestation of the motherboard.

## Genuinely hardware-only remainder

Speaker intelligibility, physical HDA/EAPD routing, real keyboard behavior, TPM platform behavior and ASUS-specific firmware timing require observation on the actual machine.
