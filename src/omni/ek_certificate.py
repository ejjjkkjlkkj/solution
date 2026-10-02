"""
Certificat EK du constructeur, lu par Windows (Get-TpmEndorsementKeyInfo, composant natif).

Sur un fTPM AMD le certificat n'est pas dans la NVRAM du TPM : Windows le recupere
aupres du service du constructeur et le met en cache. Ce module ne telecharge rien
lui-meme et n'ecrit rien.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

_SCRIPT = r"""
$e = Get-TpmEndorsementKeyInfo -Hash Sha256
$certs = @($e.ManufacturerCertificates) + @($e.AdditionalCertificates) | Where-Object { $_ }
$out = foreach ($c in $certs) {
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c)
  $aia = ($c.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' })
  [pscustomobject]@{
    subject = $c.Subject; issuer = $c.Issuer; serial = $c.SerialNumber
    not_before = $c.NotBefore.ToString('o'); not_after = $c.NotAfter.ToString('o')
    sha256 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)).Replace('-', '').ToLower()
    modulus = if ($rsa) { [BitConverter]::ToString($rsa.ExportParameters($false).Modulus).Replace('-', '').ToLower() } else { $null }
    aia = if ($aia) { $aia.Format($false) } else { $null }
    ek_public_key_hash = $e.PublicKeyHash
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


class EkCertificateError(RuntimeError):
    pass


def read_windows() -> list[dict]:
    if not sys.platform.startswith("win"):
        raise EkCertificateError("EK certificate lookup needs Windows")
    proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _SCRIPT],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise EkCertificateError(proc.stderr.strip() or "no EK certificate returned")
    data = json.loads(proc.stdout)
    certs = data if isinstance(data, list) else [data]
    for cert in certs:
        found = re.search(r"https?://\S+", cert.get("aia") or "")
        cert["aia"] = found.group(0) if found else None
    return certs


def rsa_certificate(certs: list[dict]) -> dict | None:
    return next((c for c in certs if c.get("modulus")), None)
