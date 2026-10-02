# Read-only TPM 2.0 access

`omni tpm-read` talks to the TPM through TPM Base Services (`tbs.dll`) using
only `ctypes`. It sends three read commands: `TPM2_GetCapability` (manufacturer,
firmware version), `TPM2_GetRandom` and `TPM2_PCR_Read` (SHA-256 bank, PCR 0 to 7).
It never creates keys and never writes to the TPM. Responses are validated for
size, response code and truncation.

    omni tpm-read --format text

The output includes a SHA-256 over the PCR values. This is a reading, not
attestation: the `tpm_quote` gate stays unattested because `TPM2_Quote` needs a
signing key, and creating one writes to the TPM. `quote` is always `null`.
