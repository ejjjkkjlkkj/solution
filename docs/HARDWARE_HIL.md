# Physical AMD hardware-in-the-loop

This workflow deliberately does not modify ASUS OEM firmware.

A hosted Linux runner builds one immutable OmniProbe.efi and removable boot image. The physical Windows self-hosted runner then:

1. asserts it is the intended ASUS M1603QA / Ryzen 7 5800H platform;
2. captures BIOS, board, Secure Boot, TPM, VBS, HDA and signed-driver inventory;
3. executes the exact same EFI image under QEMU;
4. executes the exact same EFI image under VMware Workstation;
5. captures serial/debug evidence and SHA-256 hashes.

The EFI probe emits OMNI_UEFI_PASS through both QEMU debugcon and a standard 16550 COM1 UART. The COM1 path provides backend-independent evidence for VMware.

This proves that software artifacts and virtualized firmware backends run on the actual target host. It does not prove physical ASUS firmware execution, physical speaker output, real pre-OS keyboard behavior, TPM quoting, or OEM HDA routing. Those remain explicit hardware gates.
