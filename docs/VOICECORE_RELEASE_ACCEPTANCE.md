# VoiceCore release acceptance

A syntactically valid phoneme stream or clean PCM buffer is not a finished voice.

VoiceCore may report `VOICE_RELEASE_PASS` only when every required gate has explicit
`PASS` evidence. Missing, skipped, blocked, timed-out and subjective-but-unmeasured
claims remain blockers.

## Software gates

- semantic frontend;
- stable phoneme stream ABI;
- real 48 kHz PCM renderer;
- deterministic rendering for fixed inputs and fixed model state;
- PCM cleanliness;
- bounded text and stream handling;
- bounded renderer memory;
- measured first-audio latency;
- measured interrupt latency;
- long-run stability;
- reproducible voice artifact.

## Perceptual gates

- French intelligibility;
- French naturalness;
- intelligibility of firmware-specific terms, acronyms, values and confirmations.

These gates require listening evidence. They cannot be inferred from waveform validity,
SNR, spectral statistics or a successful boot.

## Hardware gates

- QEMU/OVMF PCM path;
- VMware UEFI audio path;
- physical HDA output;
- physical-speaker intelligibility.

The physical-speaker gate requires human confirmation. CI must not convert an HDA DMA
success or a non-silent PCM capture into an audible/intelligible PASS.

## Renderer policy

The previous formant/Klatt experiments are references and regression material only.
They are not accepted as the target renderer merely because they are small or
deterministic. The target renderer must pass the perceptual gates without adding an
OS speech API or external screen reader dependency.


## Bounded interruptible PCM queue

The host reference includes a bounded PCM16LE queue for screen-reader playback.
The default queue holds at most 9600 frames (200 ms at 48 kHz) and emits at most
960 frames (20 ms) per default pop. Overflow is an error, never a silent drop.
Cancellation empties the queue immediately and increments a generation counter so
a device/backend can reject stale audio produced before the interruption.

These queue timings are transport bounds, not measured end-to-end speech latency.
The `first_audio_latency` and `interrupt_latency` release gates remain blocked
until the real renderer and firmware audio path are measured.
