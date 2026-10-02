# Host hardware inventory

`omni host-inventory` describes the machine it runs on using only the Python
standard library and Windows APIs already present on the OS. No third-party
package and no subprocess is involved.

| Source | API | Fields |
|---|---|---|
| SMBIOS | `GetSystemFirmwareTable('RSMB')` via `ctypes` | BIOS vendor/version/date, system manufacturer/product, Type 1 UUID |
| Registry | `winreg` | baseboard, CPU, Secure Boot state, HDA codecs, keyboard devices |
| TPM Base Services | `Tbsi_GetDeviceInfo` via `ctypes` | TPM presence, version, interface type |

The SMBIOS UUID is read the same way OmniProbe reads it, so it can be passed to
`tools/verify_uefi_evidence.py --expected-platform-uuid`.

## Identity check

    omni host-inventory --expect-asus-m1603qa
    omni host-inventory --expect-uuid <SMBIOS-Type-1-UUID>

Exit code 1 on any mismatch or missing field. Missing data is never guessed.

## What this is not

The inventory attests **no** hardware gate. `gates_attested` is always empty.
`asus_oem_uefi`, `physical_keyboard`, `physical_hda_audio`, `physical_latency`
and `tpm_quote` need evidence produced on the hardware: a pre-OS boot of the
challenge-bound OmniProbe media, a TPM quote, an acoustic/latency measurement.
`windows_qemu_hil` and `windows_vmware_hil` need the HIL runs themselves.
The inventory only confirms the preconditions (identity, codec present,
TPM 2.0 present, Secure Boot state) and gives a SHA-256 over its canonical JSON.

Outside Windows the command reports `platform_supported: false` and fails.
