#!/usr/bin/env bash
set -euo pipefail

OPAM_REPOSITORY_SHA="6261f3c853ae417b354c06496e8458053131f14b"
OCAML_PACKAGE="ocaml-base-compiler.5.3.0"
FRAMAC_PACKAGE="frama-c.33.0"
ALT_ERGO_PACKAGE="alt-ergo.2.6.4"

ROOT="${RUNNER_TEMP:-/tmp}/omni-opam-root"
REPO="${RUNNER_TEMP:-/tmp}/omni-opam-repository"
rm -rf "$ROOT" "$REPO"

git clone https://github.com/ocaml/opam-repository.git "$REPO"
git -C "$REPO" checkout --detach "$OPAM_REPOSITORY_SHA"
test "$(git -C "$REPO" rev-parse HEAD)" = "$OPAM_REPOSITORY_SHA"

export OPAMROOT="$ROOT"
opam init --bare --disable-sandboxing --no-setup -y default "file://$REPO"
opam switch create omni-formal "$OCAML_PACKAGE" -y
eval "$(opam env --switch=omni-formal --set-switch)"
opam install -y "$FRAMAC_PACKAGE" "$ALT_ERGO_PACKAGE"

frama-c -version | grep -F "33.0 (Arsenic)"
alt-ergo --version
opam switch export "${GITHUB_WORKSPACE:-$PWD}/formal-toolchain.opam.export"
opam list --installed --columns=name,version > "${GITHUB_WORKSPACE:-$PWD}/formal-toolchain-packages.txt"
printf 'OPAM_REPOSITORY_SHA=%s\nOCAML_PACKAGE=%s\nFRAMAC_PACKAGE=%s\nALT_ERGO_PACKAGE=%s\n' \
  "$OPAM_REPOSITORY_SHA" "$OCAML_PACKAGE" "$FRAMAC_PACKAGE" "$ALT_ERGO_PACKAGE" \
  > "${GITHUB_WORKSPACE:-$PWD}/formal-toolchain-pins.txt"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'OPAMROOT=%s\nOPAMSWITCH=omni-formal\n' "$ROOT" >> "$GITHUB_ENV"
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then
  opam var bin --switch=omni-formal >> "$GITHUB_PATH"
fi

echo "export OPAMROOT=$ROOT"
echo 'eval "$(opam env --switch=omni-formal --set-switch)"'
