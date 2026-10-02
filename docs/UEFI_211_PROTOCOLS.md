# Couverture protocoles UEFI 2.10 / 2.11

`omni.uefi211` analyse un binaire UEFI (`.efi`, `.fd`, `.bin`, `.img`, `.rom`)
et detecte la presence des sous-protocoles exposes par les toutes dernieres
specifications :

| Spec release | Date          | Cles notables                                                   |
|--------------|---------------|-----------------------------------------------------------------|
| UEFI 2.10    | aout 2022     | Virtual Keyboard Protocol, HII Database protocol complet        |
| UEFI 2.10 Errata A | aout 2024 | Corrections de bugs, clarifications HII                         |
| UEFI 2.11    | 2025         | PI 1.9 alignement, simplifications utilisateur                  |

## Categories scannees

| Categorie   | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `hii`       | HII complet (PackageList, ConfigRouting, ConfigAccess, Font, String, Image, Database, ConfigKeywordHandler) |
| `audio`     | Audio Protocol : HDA Codec, HDA Link, USB Audio Class (GSoC 2024), VoiceOutput (draft), Beep Protocol |
| `input`     | Virtual Keyboard (UEFI 2.10), USB HID, USB IO, Simple Text Input (+ Ex) |
| `network`   | HTTP, REST, TCP, UDP, DHCPv6, DNSv6, IPv4/v6, Network Interface Identifier |
| `vpn`       | WireGuard, OpenVPN, IPsec/strongSwan, OpenSSL/TLS, ZeroTier                |
| `ids`       | Suricata, Snort, Zeek/Bro, iptables/nftables, Wazuh, CrowdSec, auditd, Sysmon, Windows Defender |

## Utilisation

```bash
# Analyse d'un binaire UEFI
python -m omni.cli uefi211-check ./monoplatform.efi

# Utilisation en module
from omni.uefi211 import analyze
cov = analyze(open("monoplatform.bin", "rb").read())
print(cov.passed())                    # True/False
print(cov.by_category["audio"])        # ('hda_codec', 'voice_output')
print(cov.uefi_version)                # '2.10', '2.11', '2.9', 'unknown', ...
```

## Garanties

- **Aucun effet de bord** : le module prend des octets, rend un objet JSON-compatible.
- **Aucune dependance externe** : stdlib uniquement.
- **Detecte ASCII et UTF-16LE** : les firmwares UEFI melangent les deux representations.
- **Verdict fail-closed** : `passed()` exige `uefi_version_supported == True` ET une
  couverture >= 1 dans chaque categorie requise. Un firmware non-UEFI 2.10/2.11
  ne peut pas recevoir PASS meme s'il expose accidentellement un nom de protocole.

## Limites

- Pas de decompression LZMA : si une image utilise la compression, les chaines
  embarques peuvent etre inaccessibles.
- Pas d'execution : analyse statique uniquement.
- Pas de verification de signature : la presence d'un nom de protocole ne prouve
  pas que le firmware l'implementent correctement.

## Sortie JSON

```json
{
  "bytes_total": 12345,
  "sha256": "...",
  "uefi_version": "2.10",
  "uefi_version_supported": true,
  "categories": {
    "hii":     ["hii_package_list", "hii_font"],
    "audio":   ["hda_codec", "voice_output"],
    "input":   ["virtual_keyboard", "usb_hid"],
    "network": ["http"],
    "vpn":     [],
    "ids":     []
  },
  "hits": [
    {"key": "hii_package_list", "category": "hii",    "offset": 1024, "signature": "EFI_HII_PACKAGE_LIST_PROTOCOL"},
    {"key": "voice_output",     "category": "audio",  "offset": 2048, "signature": "VoiceOutput"},
    ...
  ],
  "summary": {
    "matched_total": 5,
    "matched_by_category": {"hii": 2, "audio": 2, "input": 2, "network": 1, "vpn": 0, "ids": 0}
  }
}
```

## Caveats specifiques

### UEFI Audio Protocol (2.10/2.11)

L'arxiv paper `1712.03186` (2017) avait note qu'**il n'existait pas de protocole
audio dans la spec UEFI**. Depuis, le projet GSoC 2024 d'Ethin Probst (parrainé
par Ray Ni et Leif Lindholm d'Intel) a propose un USB Audio Class driver pour
EDK2 / QEMU, qui sert de base au draft `EFI_USB_AUDIO` qu'on cherche dans cette
analyse.

Tant que ce protocole n'est pas officiellement ratifié, la presence de la
signature `EFI_USB_AUDIO` ou `UsbAudioClass` indique un firmware experimental
ou tres recent (UEFI 2.11+).

### HDA Specification 1.0a

Les controleurs HDA d'Intel sont toujours a PCI `0:27:0` (bus 0, device 27,
function 0) sur les plateformes recentes. Le firmware ASUS AMD peut utiliser
un routage different : la presence de `HdaCodec` ou `gHdaController` ne suffit
pas pour determiner la conformite materielle.

### Network stack

Les protocoles `EFI_HTTP_PROTOCOL`, `EFI_TCP_PROTOCOL` etc. sont definis dans
la spec depuis longtemps, mais leur presence simultanee dans un meme firmware
est rare : les impletes embarquent generalement un seul transport (HTTP pour
le firmware update a distance, par exemple).

## Pour aller plus loin

- Cross-referencer avec `firmware.inspect()` pour detecter les Firmware Volumes
  malformes.
- Cross-referencer avec `ifr.inspect_file()` pour la couverture IFR (HII/IFR
  bridge deja couvert par le module `ifr`).
- Comparer deux firmwares avec la meme couverture pour reperer les patches
  applicatifs (delta analysis).