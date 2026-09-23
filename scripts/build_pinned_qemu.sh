#!/usr/bin/env bash
set -euo pipefail

QEMU_TAG="v11.1.1"
QEMU_SHA="c3d48b7d1e89604920e5b81b91140c2ad39a1943"

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 OUTPUT_QEMU_SYSTEM [OUTPUT_QEMU_IMG]" >&2
  exit 2
fi

OUTPUT="$(readlink -f "$1")"
IMG_OUTPUT=""
if [[ $# -eq 2 ]]; then
  IMG_OUTPUT="$(readlink -f "$2")"
fi
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

ninja -C build qemu-system-x86_64 qemu-img
test -x build/qemu-system-x86_64
mkdir -p "$(dirname "$OUTPUT")"
cp build/qemu-system-x86_64 "$OUTPUT"
if [[ -n "$IMG_OUTPUT" ]]; then
  mkdir -p "$(dirname "$IMG_OUTPUT")"
  cp build/qemu-img "$IMG_OUTPUT"
fi

"$OUTPUT" --version
sha256sum "$OUTPUT"
printf 'QEMU_SOURCE_TAG=%s\nQEMU_SOURCE_SHA=%s\n' "$QEMU_TAG" "$QEMU_SHA"
