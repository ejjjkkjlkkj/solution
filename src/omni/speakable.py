"""
Rendu texte lineaire, adapte aux lecteurs d'ecran, des rapports de la CLI.

Regles : le verdict vient en premiere ligne ; une information par ligne, en
phrase complete ; aucun tableau, aucune couleur, aucun symbole decoratif ni
emoji ; aucun identifiant technique brut quand un libelle existe ; le rapport
se termine par une ligne de fin explicite. Les fonctions sont pures
(dict -> str) : le meme texte sert a l'ecran, au braille et a la synthese.
"""

from __future__ import annotations

from typing import Any

_STATUS = {"OK": "reussi", "PARTIEL": "partiel", "ABSENT": "absent", "PASS": "reussi", "FAIL": "echec"}
_CATEGORY = {
    "a11y": "Accessibilite",
    "vpn": "VPN",
    "ids": "Detection et prevention d'intrusion",
    "hii": "Formulaires HII",
    "audio": "Audio",
    "input": "Entree clavier",
    "network": "Reseau",
}
_RUNNING = {True: "en cours d'execution", False: "arrete", None: "etat inconnu"}


def _lines(verdict: str, body: list[str]) -> str:
    return "\n".join([verdict, *body, "Fin du rapport."]) + "\n"


def render_host_scan(data: dict[str, Any], passed: bool) -> str:
    body = [f"Systeme : {data.get('platform', 'inconnu')}."]
    for cat, items in sorted(data.get("categories", {}).items()):
        found = [i for i in items if i.get("installed")]
        body.append(f"{_CATEGORY.get(cat, cat)} : {len(found)} installes sur {len(items)} recherches.")
        for item in found:
            body.append(f"{item['label']} : installe, {_RUNNING[item.get('running')]}.")
    return _lines("Scan de l'hote reussi." if passed else "Scan de l'hote incomplet.", body)


def render_chain(data: dict[str, Any]) -> str:
    stages = data.get("stages", [])
    ok = sum(1 for s in stages if s.get("status") == "OK")
    verdict = (
        "Chaine complete reussie."
        if data.get("passed")
        else f"Chaine incomplete : {ok} etapes reussies sur {len(stages)}."
    )
    fw = data.get("firmware", {})
    body = [f"Firmware : {fw.get('bytes_total', 0)} octets, version UEFI {fw.get('uefi_version', 'inconnue')}."]
    for n, s in enumerate(stages, 1):
        status = _STATUS.get(s.get("status", ""), "inconnu")
        body.append(
            f"Etape {n} sur {len(stages)}, {s.get('label', s.get('stage'))} : {status}, "
            f"{s.get('matched', 0)} trouves sur {s.get('expected', 0)} attendus."
        )
        if s.get("keys"):
            body.append("Detail : " + ", ".join(s["keys"]) + ".")
    return _lines(verdict, body)


def render_uefi211(data: dict[str, Any], passed: bool) -> str:
    supported = "oui" if data.get("uefi_version_supported") else "non"
    body = [
        f"Image de {data.get('bytes_total', 0)} octets, version UEFI {data.get('uefi_version', 'inconnue')}.",
        f"Version prise en charge : {supported}.",
    ]
    for cat, n in sorted(data.get("summary", {}).get("matched_by_category", {}).items()):
        body.append(f"{_CATEGORY.get(cat, cat)} : {n} protocoles detectes.")
    return _lines("Couverture UEFI suffisante." if passed else "Couverture UEFI insuffisante.", body)


def render_inventory(data: dict[str, Any], identity: dict[str, Any] | None = None) -> str:
    if not data.get("platform_supported"):
        return _lines("Inventaire impossible : systeme non pris en charge.", [])
    f, tpm = data.get("fields", {}), data.get("tpm", {})
    sb = f.get("secure_boot_enabled")
    secure_boot = "inconnu." if sb is None else ("active." if sb else "desactive.")
    tpm_line = f"TPM : present, version {tpm.get('version')}." if tpm.get("present") else "TPM : absent."
    hda = f.get("hda_devices", [])
    body = [
        f"Machine : {f.get('system_manufacturer', 'inconnu')}, modele {f.get('baseboard_product', 'inconnu')}.",
        f"Processeur : {f.get('cpu', 'inconnu')}.",
        f"BIOS : {f.get('bios_vendor', 'inconnu')}, version {f.get('bios_version', 'inconnue')}, "
        f"du {f.get('bios_release_date', 'date inconnue')}.",
        f"Mode de demarrage : {data.get('firmware_mode', 'inconnu')}.",
        f"Secure Boot : {secure_boot}",
        tpm_line,
        f"Peripheriques audio HDA : {len(hda)}.",
        *[f"Audio : {d.get('description') or 'sans nom'}." for d in hda],
        f"Claviers internes detectes : {len(f.get('keyboards', []))}.",
    ]
    if f.get("system_uuid"):
        body.append("Identifiant SMBIOS disponible dans la sortie JSON.")
    body += [f"Erreur de lecture : {e}." for e in data.get("errors", [])]
    body.append("Cet inventaire n'atteste aucun gate materiel.")
    if identity is None:
        verdict = "Inventaire termine."
    elif identity["status"] == "PASS":
        verdict = "Identite de la machine conforme."
    else:
        verdict = "Identite de la machine non conforme."
        body += [f"Ecart : {m}." for m in identity["mismatches"]]
    return _lines(verdict, body)


def render_tpm(data: dict[str, Any]) -> str:
    pcrs = data.get("pcrs", {})
    body = [
        f"Fabricant du TPM : {data.get('manufacturer') or 'inconnu'}.",
        f"Version du firmware : {data.get('firmware_version') or 'inconnue'}.",
        f"Registres PCR lus : {len(pcrs)}.",
        f"Condensat de lecture : {data.get('pcr_composite', 'inconnu')}.",
    ]
    quote = data.get("quote")
    if quote:
        v = quote["verification"]
        body.append("Quote produit et verifie localement : " + ("valide." if v["valid"] else "INVALIDE.")
                    + " Signature " + ("bonne" if v["signature_valid"] else "mauvaise")
                    + ", nonce " + ("conforme" if v["nonce_match"] else "different")
                    + ", condensat de PCR " + ("conforme." if v["pcr_digest_match"] else "different.")
                    + " Cle transitoire vidangee.")
    else:
        body.append("Lecture seule : aucun quote n'a ete produit, le gate tpm_quote n'est pas atteste.")
    return _lines("Lecture du TPM reussie.", body)
