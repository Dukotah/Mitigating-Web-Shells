#!/usr/bin/env bash
# Build a specific YARA release from source into a prefix.
# Usage: ci/build-yara.sh <version> <prefix>      e.g. ci/build-yara.sh 4.5.8 "$HOME/yara-4.5.8"
set -euo pipefail
ver="$1"
prefix="$2"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL "https://github.com/VirusTotal/yara/archive/refs/tags/v${ver}.tar.gz" | tar -xz -C "$work"
cd "$work/yara-${ver}"
./bootstrap.sh >/dev/null
# YARA 3.x predates OpenSSL 3 and warns on deprecated APIs; do not fail on warnings.
CFLAGS="-O2 -Wno-deprecated-declarations" ./configure --prefix="$prefix" --disable-shared >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
"$prefix/bin/yara" --version
