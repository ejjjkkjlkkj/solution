"""
Certificat EK du constructeur, lu par Windows (Get-TpmEndorsementKeyInfo, composant natif).

Sur un fTPM AMD le certificat n'est pas dans la NVRAM du TPM : Windows le recupere
aupres du service du constructeur et le met en cache. Ce module ne telecharge rien
lui-meme et n'ecrit rien.
"""

from __future__ import annotations

import json
import re
import shutil
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


_CHAIN_SCRIPT = r"""
$ek = (Get-TpmEndorsementKeyInfo -Hash Sha256).AdditionalCertificates | Select-Object -First 1
$X = [Security.Cryptography.X509Certificates.X509Certificate2]
$extra = @(); $cur = $ek; $root = $null; $hashes = @()
for ($i = 0; $i -lt 4 -and -not $root; $i++) {
  $aia = $cur.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }
  $m = if ($aia) { [regex]::Match($aia.Format($false), 'URL=(https?://[^\s,]+)') } else { $null }
  if (-not $m -or -not $m.Success) { break }
  $data = (Invoke-WebRequest $m.Groups[1].Value -UseBasicParsing -TimeoutSec 30).Content
  $c = $X::new([byte[]]$data)
  $hashes += [pscustomobject]@{ url = $m.Groups[1].Value; subject = $c.Subject
    sha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)).Replace('-', '').ToLower() }
  if ($c.Subject -eq $c.Issuer) { $root = $c } else { $extra += $c; $cur = $c }
}
$ok = $false; $status = 'no self-signed root reached'
if ($root) {
  $ch = [Security.Cryptography.X509Certificates.X509Chain]::new()
  $ch.ChainPolicy.TrustMode = 'CustomRootTrust'; $ch.ChainPolicy.CustomTrustStore.Add($root) | Out-Null
  foreach ($c in $extra) { $ch.ChainPolicy.ExtraStore.Add($c) | Out-Null }
  $ch.ChainPolicy.RevocationMode = 'NoCheck'; $ch.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid'
  $ok = $ch.Build($ek); $status = ($ch.ChainStatus | ForEach-Object { $_.Status }) -join ','
}
ConvertTo-Json -InputObject ([pscustomobject]@{ signatures_valid = $ok; status = $status; fetched = @($hashes) }) -Depth 4 -Compress
"""


def verify_chain_online() -> dict:
    """Telecharge la chaine AIA (HTTP, URL du certificat) et verifie les signatures jusqu'a la racine auto-signee.

    La racine est celle publiee par le constructeur : ses signatures sont verifiees, mais son authenticite
    n'est ancree dans aucun magasin de confiance ; les empreintes telechargees sont renvoyees.
    """
    if not sys.platform.startswith("win"):
        raise EkCertificateError("EK chain check needs Windows")
    shell = shutil.which("pwsh")  # TrustMode=CustomRootTrust n'existe pas dans Windows PowerShell 5.1 (.NET Framework)
    if shell is None:
        raise EkCertificateError("PowerShell 7 (pwsh) is required for the chain check")
    proc = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", _CHAIN_SCRIPT],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise EkCertificateError(proc.stderr.strip() or "chain check failed")
    return json.loads(proc.stdout)
