# TPM 2.0 access

`omni tpm-read` talks to the TPM through TPM Base Services (`tbs.dll`) using
only `ctypes`. By default it sends three read commands: `TPM2_GetCapability`
(manufacturer, firmware version), `TPM2_GetRandom` and `TPM2_PCR_Read` (SHA-256
bank, PCR 0 to 7). It never creates keys and never writes to the TPM. Responses
are validated for size, response code and truncation.

    omni tpm-read --format text

Without `--quote`, `quote` is `null` and the `tpm_quote` gate stays unattested.

## Optional quote (writes to the TPM)

    omni tpm-read --quote --format text

`--quote` creates a **transient** ECDSA P-256 restricted signing key under the
owner hierarchy (empty auth, password session), signs `TPM2_Quote` over PCR 0 to
7 with a fresh 32-byte TPM nonce, and always flushes the key (`TPM2_FlushContext`),
even on failure. Nothing is persisted. The signature, the nonce, the quote type
and the PCR digest are then verified locally in pure Python (ECDSA over P-256),
and PCRs must be unchanged between the two reads around the quote.

Limit: the key has no certificate chain (it is not an endorsement-certified AK),
so the quote proves the reading is internally consistent and was signed by this
TPM during this call, not the platform identity. It can fail on machines where the
owner hierarchy is authorized or locked out; the error is reported and nothing is
left loaded.

## Certified quote (`--attest`)

    omni tpm-read --attest --format text

Adds the manufacturer certificate to the chain. All objects are transient and
flushed, including on failure:

1. An RSA-2048 endorsement key (EK) is created from the standard TCG template
   and its modulus is compared with the EK certificate that Windows retrieved
   from the manufacturer (`Get-TpmEndorsementKeyInfo`; on this AMD fTPM it is
   not in TPM NV, so `omni.ek_certificate` only reads Windows' copy and
   downloads nothing).
2. An ECDSA P-256 restricted signing key (AK) is created; its attributes
   (fixedTPM, fixedParent, restricted, sign) are checked.
3. `MakeCredential` / `ActivateCredential` (policy session with
   `PolicySecret` on the endorsement hierarchy) proves the AK lives in the
   same TPM as the certified EK.
4. The AK signs `TPM2_Quote`; signature, nonce, PCR digest and PCR stability
   are verified locally.

Limits: `MakeCredential` is run by the same TPM, so the binding is proven by
the TPM rather than by independent software; the AMD root is not in the
Windows trust store.

`--attest --fetch-chain` additionally downloads the certificate chain from the
AIA URLs inside the EK certificate (HTTP, needs PowerShell 7) and verifies every
signature up to the self-signed root (EK <- PRG-RN <- AMDTPM on this machine).
The downloaded SHA-256 values are reported; the root's authenticity is not
anchored in any trust store, only its signatures are checked.
