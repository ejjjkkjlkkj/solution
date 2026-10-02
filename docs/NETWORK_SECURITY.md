# Pile reseau de confidentialite + IDS / IPS

Cette couche couvre la **chaine reseau** du boot UEFI jusqu'a l'OS : VPN,
IDS et IPS. Elle se decompose en deux sous-modules :

- `omni.uefi211` : embarque dans le firmware UEFI (couverture statique).
- `omni.host_chain` : tools heberges sur l'OS hote (presence et etat actif).

## Stack prise en charge

### VPN (chainage confidentiel)

| Outil              | Windows | Linux | macOS | Note                                              |
|--------------------|:-------:|:-----:|:-----:|----------------------------------------------------------------|
| WireGuard          |   oui   |  oui  |  oui  | Cible de reference pour le chainage moderne      |
| OpenVPN            |   oui   |  oui  |  oui  | Plus ancien, mature, bien supporte              |
| IPsec / strongSwan |   oui   |  oui  |  -    | Windows IKEv2 natif (`ikeext.dll`)               |
| OpenSSL / TLS      |   oui   |  oui  |  oui  | Requis pour les terminaisons TLS en UEFI 2.10+  |
| ZeroTier           |   oui   |  oui  |  oui  | Option overlay                                      |
| Windows VPN integre|   oui   |  -    |  -    | `raserver.exe`, VPN natif Microsoft                |

### IDS / IPS (chainage securite)

| Outil              | Type | Windows | Linux | macOS |
|--------------------|------|:-------:|:-----:|:-----:|
| Windows Defender   | IPS  |   oui   |  -    |  -    |
| Suricata           | IDS+IPS |   -  |  oui  |  -    |
| Snort              | IDS+IPS |   -  |  oui  |  -    |
| Zeek (Bro)         | IDS  |   -    |  oui  |  -    |
| iptables / nftables| IPS  |   -    |  oui  |  -    |
| Wazuh Agent        | IDS+SIEM | oui |  oui  |  -    |
| CrowdSec           | IPS collaboratif | - | oui |  -    |
| auditd            |      |   -    |  oui  |  -    |
| Sysmon             | host IDS | oui |   -  |  -    |
| ClamAV             | AV (proche IDS) | oui | oui | - |

## Pourquoi ces choix

- **Suricata** + **Snort** : les moteurs IDS/IPS les plus deployes en
  production. Les deux supportent l'inline IPS (mode NFQUEUE/AF_PACKET).
- **Wazuh** : agent SIEM open-source tres repandu, sert a la fois d'IDS
  (regles OSSEC/Wazuh) et de collecteur de logs.
- **CrowdSec** : IPS collaboratif moderne, alternative (exchange-) open-source a
  Fail2ban avec blocklist partagee.
- **auditd** : composant Linux standard pour l'audit kernel (syscalls, fichiers).
- **Sysmon** : equivalent cote Windows, fourni par Sysinternals/Microsoft.
- **Windows Defender** : IPS natif Windows, present par defaut depuis Win10.

## Caveats

### Detection live vs hints

Le scan host scanne la machine reelle et detecte les services en cours
d'execution. En CI, on fournit une liste de hints (`scan_file_hints`) pour
eviter les faux positifs / faux negatifs.

### Faux positifs

Sur cette machine-ci (test live) :
- NVDA est installe et tourne (`running=True`).
- JAWS est installe mais pas en cours d'execution (`running=False`).
- Windows Defender est installe mais le processus `MsMpEng` n'est pas dans la
  liste des process en cours (possiblement sandboxe ou service demarre en
  lazy-mode).

On remonte `running=None` quand on ne peut pas conclure, jamais `False`
arbitrairement.

### Faux negatifs

Les outils heberges en kernel-space (WireGuard module, eBPF/XDP) peuvent
echapper a la detection par chemin / processus. Pour aller plus loin, il
faudrait interroger `ip link`, `lsmod`, `bpftool` -- hors scope actuel.

## Aggregation via `end_to_end`

Le rapport final agrege 6 etapes :
1. `uefi_firmware` : firmware UEFI charge.
2. `uefi_accessibility` : HII + Audio + Input UEFI 2.10/2.11.
3. `uefi_network` : stack reseau UEFI (HTTP / REST / TCP / DHCPv6).
4. `os_accessibility` : screen reader OS (NVDA, JAWS, Orca...).
5. `network_security` : VPN hote (chainage confidentiel).
6. `intrusion` : IDS / IPS hote (chainage securite).

`report.passed()` exige que **chaque** etape ait au moins une detection.
C'est volontaire : une accessibilite pre-OS native sans VPN equivalent n'a
pas de sens (les donnees vocales pourraient fuiter en clair).

## Liens

- `docs/UEFI_211_PROTOCOLS.md` : couverture firmware.
- `docs/HOST_ACCESSIBILITY_CHAIN.md` : scanner OS.
- `omni.ceiling.CHECK_GATE_KEYS` : agregation runtime (optionnelle, distincte
  des `REQUIRED_SOFTWARE_GATES`).