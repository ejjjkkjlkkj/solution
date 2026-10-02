# Screen-reader friendly CLI output

`uefi211-check`, `host-scan`, `host-inventory` and `chain-report` accept
`--format text` (or `OMNI_FORMAT=text` in the environment). JSON stays the
default so scripts and CI are unaffected, and exit codes are identical in both
formats.

The text report follows fixed rules (`omni.speakable`):

- the verdict is the first line, so it is the first thing read;
- one fact per line, as a full sentence, with no tables, colors, box drawing,
  arrows or emoji;
- stage counters are spoken in full ("Etape 2 sur 6");
- the report ends with the explicit line "Fin du rapport.";
- renderers are pure functions (dict to str), so the same text serves the
  screen, a braille display and speech synthesis.

Set it once for a session:

    $env:OMNI_FORMAT = "text"

## Running-state detection fix

`host-scan` previously reported Windows Defender as stopped because it looked
for a process named after the service. Each hint is now probed both as a
service (`sc query`) and as a process; the state is running if any probe says
so, stopped only if a probe answered no, and unknown otherwise.
