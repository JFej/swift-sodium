#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="${MISE_PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
: "${LIBSODIUM_VERSION:?Run this command through mise}"
: "${LIBSODIUM_RELEASE:?Run this command through mise}"
: "${LIBSODIUM_SHA256:?Run this command through mise}"

BUILD_ROOT="${SODIUM_BUILD_ROOT:-$PROJECT_ROOT/Build}"
VARIANTS_ROOT="${SODIUM_VARIANTS_ROOT:-$BUILD_ROOT/variants}"
CACHE_ROOT="${SODIUM_CACHE_ROOT:-$BUILD_ROOT/cache}"

cpu_count() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.logicalcpu
  else
    getconf _NPROCESSORS_ONLN
  fi
}

fetch_libsodium() {
  mkdir -p "$CACHE_ROOT"
  local archive="$CACHE_ROOT/libsodium-$LIBSODIUM_VERSION.tar.gz"
  if [[ ! -f "$archive" ]]; then
    curl --fail --location --retry 3 \
      "https://github.com/jedisct1/libsodium/releases/download/$LIBSODIUM_RELEASE/libsodium-$LIBSODIUM_VERSION.tar.gz" \
      --output "$archive"
  fi

  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  fi
  if [[ "$actual" != "$LIBSODIUM_SHA256" ]]; then
    echo "libsodium checksum mismatch: expected $LIBSODIUM_SHA256, got $actual" >&2
    exit 1
  fi
  printf '%s\n' "$archive"
}

extract_libsodium() {
  local identifier="$1"
  local work_root="$BUILD_ROOT/work/$identifier"
  mkdir -p "$work_root"
  local archive
  archive="$(fetch_libsodium)"
  tar -xzf "$archive" -C "$work_root"
  find "$work_root" -mindepth 1 -maxdepth 1 -type d -name "libsodium-$LIBSODIUM_VERSION" | head -1
}

record_variant() {
  local identifier="$1"
  local library="$2"
  local include_directory="$3"
  shift 3

  local output="$VARIANTS_ROOT/$identifier"
  mkdir -p "$output/library" "$output/include"
  cp "$library" "$output/library/$(basename "$library")"
  cp -R "$include_directory"/. "$output/include/"

  {
    printf '%s\n' '{'
    printf '  "identifier": "%s",\n' "$identifier"
    printf '  "library": "library/%s",\n' "$(basename "$library")"
    printf '%s\n' '  "supportedTriples": ['
    local index=0
    local total=$#
    local triple
    for triple in "$@"; do
      index=$((index + 1))
      if [[ $index -lt $total ]]; then
        printf '    "%s",\n' "$triple"
      else
        printf '    "%s"\n' "$triple"
      fi
    done
    printf '%s\n' '  ]'
    printf '%s\n' '}'
  } > "$output/metadata.json"
}

build_autotools_variant() {
  local identifier="$1"
  local host="$2"
  local compiler="$3"
  local archiver="$4"
  local ranlib="$5"
  local cflags="$6"
  local ldflags="$7"
  shift 7

  local source_directory
  source_directory="$(extract_libsodium "$identifier")"
  local prefix="$BUILD_ROOT/install/$identifier"
  mkdir -p "$prefix"

  (
    cd "$source_directory"
    CC="$compiler" AR="$archiver" RANLIB="$ranlib" \
      CFLAGS="$cflags" LDFLAGS="$ldflags" \
      ./configure \
        --host="$host" \
        --prefix="$prefix" \
        --disable-shared \
        --enable-static \
        --disable-dependency-tracking
    make -j"$(cpu_count)"
    make install
  )

  record_variant \
    "$identifier" \
    "$prefix/lib/libsodium.a" \
    "$prefix/include" \
    "$@"
  cp "$source_directory/LICENSE" "$VARIANTS_ROOT/$identifier/LICENSE.libsodium"
}
