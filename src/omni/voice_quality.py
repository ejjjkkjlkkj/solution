from __future__ import annotations

from dataclasses import dataclass
from math import isqrt

PCM_SAMPLE_RATE = 48_000
PCM_ALLOWED_CHANNELS = (1, 2)
PCM_MIN_RMS = 48
PCM_MAX_ABS_DC = 512


@dataclass(frozen=True, slots=True)
class PcmQualityReport:
    sample_rate: int
    channels: int
    frames: int
    peak: int
    rms: int
    dc_offset: int
    clipped_samples: int
    violations: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, object]:
        return {
            "sample_rate": self.sample_rate,
            "channels": self.channels,
            "frames": self.frames,
            "peak": self.peak,
            "rms": self.rms,
            "dc_offset": self.dc_offset,
            "clipped_samples": self.clipped_samples,
            "violations": list(self.violations),
            "status": "VOICE_PCM_CLEAN" if self.clean else "VOICE_PCM_REJECTED",
        }


def inspect_pcm16le(
    pcm: bytes | bytearray | memoryview,
    *,
    channels: int = 1,
    sample_rate: int = PCM_SAMPLE_RATE,
) -> PcmQualityReport:
    """Validate the hard cleanliness contract for VoiceCore PCM output.

    This gate checks transport/audio hygiene only. It does not claim naturalness
    or intelligibility, which require acoustic and human-listening validation.
    """
    if sample_rate != PCM_SAMPLE_RATE:
        raise ValueError("VoiceCore PCM must be 48000 Hz")
    if channels not in PCM_ALLOWED_CHANNELS:
        raise ValueError("VoiceCore PCM channels must be mono or stereo")

    data = bytes(pcm)
    frame_bytes = channels * 2
    if not data:
        raise ValueError("PCM buffer is empty")
    if len(data) % frame_bytes:
        raise ValueError("PCM buffer is not frame-aligned")

    samples = [
        int.from_bytes(data[i : i + 2], "little", signed=True)
        for i in range(0, len(data), 2)
    ]
    count = len(samples)
    frames = count // channels
    peak = max(abs(value) for value in samples)
    clipped = sum(value in (-32768, 32767) for value in samples)
    dc_offset = round(sum(samples) / count)
    rms = isqrt(sum(value * value for value in samples) // count)

    violations: list[str] = []
    if clipped:
        violations.append("clipping")
    if abs(dc_offset) > PCM_MAX_ABS_DC:
        violations.append("dc-offset")
    if rms < PCM_MIN_RMS:
        violations.append("silence-or-near-silence")

    return PcmQualityReport(
        sample_rate=sample_rate,
        channels=channels,
        frames=frames,
        peak=peak,
        rms=rms,
        dc_offset=dc_offset,
        clipped_samples=clipped,
        violations=tuple(violations),
    )
