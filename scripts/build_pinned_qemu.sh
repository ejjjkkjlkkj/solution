#!/usr/bin/env bash
set -euo pipefail

QEMU_TAG="v9.1.1"
QEMU_SHA="0ff5ab6f57a2427a3e83969b2e7dd71e04caae39"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_PATH" >&2
  exit 2
fi

OUTPUT="$(readlink -f "$1")"
WORK="${RUNNER_TEMP:-/tmp}/omni-qemu-${QEMU_SHA}"
rm -rf "$WORK"

git clone \
  --depth 1 \
  --branch "$QEMU_TAG" \
  --recurse-submodules \
  --shallow-submodules \
  https://github.com/qemu/qemu.git "$WORK"

ACTUAL="$(git -C "$WORK" rev-parse HEAD)"
if [[ "$ACTUAL" != "$QEMU_SHA" ]]; then
  echo "QEMU revision mismatch: expected $QEMU_SHA got $ACTUAL" >&2
  exit 1
fi

cd "$WORK"
./configure \
  --target-list=x86_64-softmmu \
  --disable-docs \
  --disable-gtk \
  --disable-sdl \
  --disable-opengl \
  --disable-curses \
  --disable-vnc

ninja -C build qemu-system-x86_64
test -x build/qemu-system-x86_64
mkdir -p "$(dirname "$OUTPUT")"
cp build/qemu-system-x86_64 "$OUTPUT"

"$OUTPUT" --version
sha256sum "$OUTPUT"
printf 'QEMU_SOURCE_TAG=%s\nQEMU_SOURCE_SHA=%s\n' "$QEMU_TAG" "$QEMU_SHA"
