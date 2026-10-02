from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import ceiling, end_to_end, firmware, host_chain, host_inventory, ifr, speakable, tpm_tbs, uefi211, voice_frontend, voice_pipeline, voice_quality


def _load_manifest(path: Path, label: str) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise SystemExit(f"{label} manifest must be a JSON object of string statuses")
    return data


def _emit(args: argparse.Namespace, data: dict, render) -> None:
    if args.format == "text":
        print(render(data), end="")
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(prog="omni")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("toolchain")

    fw = sub.add_parser("firmware-inspect")
    fw.add_argument("image")

    hii = sub.add_parser("ifr-inspect")
    hii.add_argument("package_list")

    speech = sub.add_parser("voice-normalize")
    speech.add_argument("text")
    speech.add_argument("--lang", choices=("fr", "en"), default="fr")

    compile_voice = sub.add_parser("voice-compile")
    compile_voice.add_argument("text")
    compile_voice.add_argument("--lang", choices=("fr", "en"), default="fr")

    pcm_check = sub.add_parser("voice-pcm-check")
    pcm_check.add_argument("pcm", type=Path)
    pcm_check.add_argument("--channels", type=int, choices=(1, 2), default=1)

    render = sub.add_parser("voice-render", help="render speech with the ST acoustic renderer")
    render.add_argument("text")
    render.add_argument("--lang", choices=("fr", "en"), default="fr")
    render.add_argument("--backend", choices=("neural", "compact"), default="neural")
    render.add_argument("--voice")
    render.add_argument("--rate", type=int, default=100)
    render.add_argument("--raw", action="store_true", help="skip VoiceCore text normalization")
    render.add_argument("--out", type=Path, required=True, help="PCM16LE 48 kHz mono WAV")

    sw = sub.add_parser("software-ceiling")
    sw.add_argument("manifest", type=Path)

    hw = sub.add_parser("hardware-boundary")
    hw.add_argument("manifest", type=Path)

    # Chain accessibilite + IPS/IDS/VPN  (runtime, optionnel)
    uefi211_cmd = sub.add_parser("uefi211-check", help="couverture protocoles UEFI 2.10/2.11 dans un binaire")
    uefi211_cmd.add_argument("image", type=Path)

    host_cmd = sub.add_parser("host-scan", help="scan OS hote (accessibilite + VPN + IDS/IPS)")
    host_cmd.add_argument("--category", choices=("a11y", "vpn", "ids"), action="append",
                          help="filtre par categorie (repetable)")

    inv_cmd = sub.add_parser("host-inventory", help="inventaire materiel (SMBIOS, registre, TPM), sans outil tiers")
    inv_cmd.add_argument("--expect-asus-m1603qa", action="store_true",
                         help="echoue si l'identite ne correspond pas a l'ASUS M1603QA / Ryzen 7 5800H")
    inv_cmd.add_argument("--expect-uuid", help="UUID SMBIOS Type 1 attendu")

    tpm_cmd = sub.add_parser("tpm-read", help="lecture seule du TPM 2.0 (proprietes, PCR 0 a 7), sans quote")

    chain_cmd = sub.add_parser("chain-report", help="rapport de bout en bout firmware + host")
    chain_cmd.add_argument("image", type=Path, help="binaire UEFI (.efi/.fd/.bin/.img)")
    chain_cmd.add_argument("--host-hints-file", type=Path,
                          help="fichier texte listant des chemins candidats (un par ligne)")
    chain_cmd.add_argument("--live", action="store_true",
                          help="effectue un scan live du systeme plutot que des hints")

    chain_eval = sub.add_parser("chain-evaluate", help="agrege un manifeste de chain statut vers {s}")
    chain_eval.add_argument("manifest", type=Path)

    for cmd in (uefi211_cmd, host_cmd, inv_cmd, tpm_cmd, chain_cmd):
        cmd.add_argument(
            "--format", choices=("json", "text"), default=os.environ.get("OMNI_FORMAT", "json"),
            help="text: rapport lineaire pour lecteur d'ecran (defaut: variable OMNI_FORMAT, sinon json)",
        )

    args = parser.parse_args()

    if args.command == "toolchain":
        print(json.dumps(ceiling.probe(), indent=2))
        return 0
    if args.command == "firmware-inspect":
        print(json.dumps(firmware.inspect(args.image), indent=2))
        return 0
    if args.command == "ifr-inspect":
        print(json.dumps(ifr.inspect_file(args.package_list), indent=2))
        return 0
    if args.command == "voice-normalize":
        tokens = voice_frontend.normalize_for_speech(args.text, args.lang)
        print(
            json.dumps(
                [{"kind": token.kind.value, "text": token.text} for token in tokens],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.command == "voice-compile":
        stream = voice_pipeline.compile_speech_stream(args.text, args.lang)
        print(json.dumps({"version": voice_pipeline.FRONTEND_STREAM_VERSION, "bytes": list(stream)}, indent=2))
        return 0
    if args.command == "voice-pcm-check":
        report = voice_quality.inspect_pcm16le(
            args.pcm.read_bytes(),
            channels=args.channels,
        )
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0 if report.clean else 1
    if args.command == "voice-render":
        from . import voice_st  # loads the ST library only when asked

        with voice_st.StRenderer(lang=args.lang, backend=args.backend, voice=args.voice, rate=args.rate) as renderer:
            result = renderer.render(args.text, normalize=not args.raw)
        args.out.write_bytes(voice_st.pcm16le_wav(result.pcm16le))
        print(json.dumps({
            "text": result.text,
            "out": str(args.out),
            "seconds": round(result.seconds, 3),
            "first_audio_ms": round(result.first_audio_ms, 1),
            "total_ms": round(result.total_ms, 1),
            "pcm": result.report.to_dict(),
        }, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.report.clean else 1
    if args.command == "software-ceiling":
        result = ceiling.evaluate(_load_manifest(args.manifest, "software ceiling"))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "SOFTWARE_CEILING_PASS" else 1
    if args.command == "hardware-boundary":
        result = ceiling.evaluate_hardware(_load_manifest(args.manifest, "hardware boundary"))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "HARDWARE_BOUNDARY_PASS" else 1
    if args.command == "uefi211-check":
        cov = uefi211.analyze_file(str(args.image))
        _emit(args, cov.as_dict(), lambda d: speakable.render_uefi211(d, cov.passed()))
        return 0 if cov.passed() else 1
    if args.command == "host-scan":
        cats = tuple(args.category) if args.category else ("a11y", "vpn", "ids")
        kwargs = {k: (k in cats) for k in ("a11y", "vpn", "ids")}
        scan = host_chain.scan_host(**kwargs)
        _emit(args, scan.as_dict(), lambda d: speakable.render_host_scan(d, scan.passed(cats)))
        return 0 if scan.passed(cats) else 1
    if args.command == "host-inventory":
        inv = host_inventory.collect()
        out = inv.to_dict()
        rc = 0 if inv.platform_supported else 1
        if args.expect_asus_m1603qa or args.expect_uuid:
            base = host_inventory.ASUS_M1603QA if args.expect_asus_m1603qa else host_inventory.IdentityExpectation()
            exp = host_inventory.IdentityExpectation(
                base.system_manufacturer, base.system_product, base.baseboard_product,
                base.cpu_contains, args.expect_uuid)
            out["identity"] = host_inventory.check_identity(inv, exp)
            rc = 0 if out["identity"]["status"] == "PASS" else 1
        _emit(args, out, lambda d: speakable.render_inventory(d, d.get("identity")))
        return rc
    if args.command == "tpm-read":
        try:
            transport, close = tpm_tbs.windows_transport()
            try:
                pcrs = tpm_tbs.read_pcrs(transport)
                data = {**tpm_tbs.identity(transport), "pcrs": {str(k): v for k, v in pcrs.items()},
                        "pcr_composite": tpm_tbs.pcr_composite(pcrs), "quote": None}
            finally:
                close()
        except tpm_tbs.TpmError as exc:
            print(f"Lecture du TPM impossible : {exc}.")
            return 1
        _emit(args, data, speakable.render_tpm)
        return 0
    if args.command == "chain-report":
        if args.live:
            host = host_chain.scan_host()
        elif args.host_hints_file:
            hints = [l for l in args.host_hints_file.read_text(encoding="utf-8").splitlines() if l.strip()]
            det = host_chain.scan_file_hints(hints)
            host = host_chain.HostScan(platform="static", detections=tuple(det))
        else:
            det = host_chain.scan_file_hints([])
            host = host_chain.HostScan(platform="empty", detections=tuple(det))
        cov = uefi211.analyze_file(str(args.image))
        report = end_to_end.build_chain(cov, host)
        _emit(args, report.as_dict(), speakable.render_chain)
        return 0 if report.passed() else 1
    if args.command == "chain-evaluate":
        result = ceiling.evaluate_chain(_load_manifest(args.manifest, "chain gates"))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "CHAIN_REPORT_PASS" else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
