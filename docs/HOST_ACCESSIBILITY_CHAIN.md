# Chaine d'accessibilite hote + IDS / IPS / VPN

`omni.host_chain` realise un scan local pour determiner :

1. **Quels outils d'accessibilite sont installes et actifs** sur la machine.
2. **Quelle pile de confidentialite reseau** est deployee (VPN).
3. **Quelle pile de detection / prevention d'intrusion** est en place (IDS/IPS).

Le scan est sans effet de bord : aucun service n'est demarre / arrete, aucun
fichier n'est modifie. On regarde les chemins, les binaires, les services.

## Couverture par plateforme

| Categorie   | Windows                                            | Linux                          | macOS                  |
|-------------|----------------------------------------------------|-------------------------------------|------------------------|
| `a11y`      | NVDA, JAWS, Narrator, SAPI, Windows Speech         | Orca, espeak, speech-dispatcher, brltty | VoiceOver, espeak |
| `vpn`       | WireGuard, OpenVPN, IPsec (IKE), Windows VPN RAS   | WireGuard, OpenVPN, strongSwan, ZeroTier |     |                      |
| `ids`       | Windows Defender, Sysmon, Wazuh Agent              | Suricata, Snort, Zeek, Wazuh, auditd, CrowdSec, ClamAV | (limite) |

## Utilisation

```bash
# Scan live de la machine (best-effort)
python -m omni.cli host-scan

# Filtre par categorie
python -m omni.cli host-scan --category a11y --category vpn
```

Sortie JSON :

```json
{
  "platform": "win32",
  "categories": {
    "a11y": [
      {"key": "nvda",  "label": "NVDA (Windows)",  "installed": true, "running": true,  "evidence": "C:\\Program Files\\NVDA"},
      {"key": "jaws",  "label": "JAWS (Freedom Sci.)", "installed": true, "running": false, "evidence": "..."}
    ],
    "vpn":   [...],
    "ids":   [...]
  }
}
```

## Pour les tests unitaires

```python
from omni import host_chain, end_to_end

# Detection sur hints uniquement (deterministe, pas de d'I/O reel).
det = host_chain.scan_file_hints([
    r"C:\Program Files\NVDA",
    "/usr/bin/wg",
    "/usr/bin/suricata",
])
host = host_chain.HostScan(platform="static", detections=tuple(det))
```

`scan_file_hints` valide un chemin si :
1. il correspond a un chemin candidat du detecteur, **OU**
2. le chemin candidat existe reellement sur le disque.

Cela rend la fonction a la fois utilisable en CI (deterministe si on fournit
tous les chemins candidats) et en production (auto-detection si on laisse la
liste vide).

## Limites

- **Pas de test d'accessibilite** : on dit "NVDA est installe", pas
  "NVDA est capable de vocaliser une notification Windows dans la locale X".
  Ce niveau de garantie necessite un test E2E avec une lib NVDA ou JAWS
  pilotee (hors scope ici).
- **Pas de detection de version** : on dit "WireGuard est la", pas
  "WireGuard 1.0.20210914". Une analyse de version ajoute une dependance
  externe (recuperer les versions a jour depuis winget/apt/brew).
- **Pas de detection de configuration** : un IDS/IPS mal configure reste
  silencieux ici. On ne peut pas lire les regles Suricata ou les politiques
  Wazuh de maniere portable.
- **Best-effort sur les processus** : `pgrep`, `tasklist`, `sc query` peuvent
  etre bloques par les politiques de securite. On remonte `None` quand on ne
  peut pas conclure, jamais `False` arbitrairement.

## End-to-end avec le firmware

Combine avec `uefi211` via `end_to_end.build_chain()` pour obtenir un rapport
de bout en bout :

```python
from omni import uefi211, host_chain, end_to_end

fw = open("firmware.bin", "rb").read()
cov = uefi211.analyze(fw)
host = host_chain.scan_host()
report = end_to_end.build_chain(cov, host)

# 6 etapes : firmware, accessibility pre-OS, network UEFI, a11y OS, VPN, IDS
print(report.passed())
for stage in report.stages:
    print(stage.status, stage.label, stage.keys)
```

Voir `docs/UEFI_211_PROTOCOLS.md` pour la partie firmware et `CHANGELOG.md`
pour l'etat des developpements.