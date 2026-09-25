from __future__ import annotations

from collections.abc import Mapping

VOICE_SOFTWARE_GATES = frozenset(
    {
        "semantic_frontend",
        "phoneme_stream_abi",
        "renderer_48khz_pcm",
        "renderer_determinism",
        "pcm_cleanliness",
        "bounded_text_and_stream",
        "bounded_renderer_memory",
        "first_audio_latency",
        "interrupt_latency",
        "long_run_stability",
        "reproducible_voice_artifact",
    }
)

VOICE_PERCEPTUAL_GATES = frozenset(
    {
        "french_intelligibility",
        "french_naturalness",
        "firmware_terms_intelligibility",
    }
)

VOICE_HARDWARE_GATES = frozenset(
    {
        "qemu_ovmf_pcm_path",
        "vmware_uefi_audio_path",
        "physical_hda_audio",
        "physical_speaker_intelligibility",
    }
)

VOICE_REQUIRED_GATES = (
    VOICE_SOFTWARE_GATES
    | VOICE_PERCEPTUAL_GATES
    | VOICE_HARDWARE_GATES
)

VOICE_ALLOWED_STATUSES = frozenset(
    {
        "PASS",
        "FAIL",
        "NOT_RUN",
        "MISSING",
        "BLOCKED",
        "SKIP",
        "CANCELLED",
        "TIMED_OUT",
    }
)


def evaluate_voice_release(statuses: Mapping[str, str]) -> dict[str, object]:
    """Return PASS only when every voice release gate has explicit PASS evidence."""
    supplied: dict[str, str] = {}
    for name, status in statuses.items():
        if not isinstance(name, str) or not name:
            raise ValueError("voice gate names must be non-empty strings")
        if not isinstance(status, str):
            raise ValueError(f"voice gate {name!r} status must be a string")
        supplied[name] = status

    missing = sorted(VOICE_REQUIRED_GATES - supplied.keys())
    unexpected = sorted(supplied.keys() - VOICE_REQUIRED_GATES)
    invalid = sorted(
        name
        for name in VOICE_REQUIRED_GATES & supplied.keys()
        if supplied[name] not in VOICE_ALLOWED_STATUSES
    )
    failed = sorted(
        name
        for name in VOICE_REQUIRED_GATES & supplied.keys()
        if supplied[name] in VOICE_ALLOWED_STATUSES and supplied[name] != "PASS"
    )
    blockers = sorted(set(missing) | set(unexpected) | set(invalid) | set(failed))

    return {
        "status": "VOICE_RELEASE_PASS" if not blockers else "VOICE_RELEASE_INCOMPLETE",
        "blockers": blockers,
        "missing": missing,
        "failed": failed,
        "invalid": invalid,
        "unexpected": unexpected,
        "software_required": sorted(VOICE_SOFTWARE_GATES),
        "perceptual_required": sorted(VOICE_PERCEPTUAL_GATES),
        "hardware_required": sorted(VOICE_HARDWARE_GATES),
        "evidence_count": len(supplied),
    }
