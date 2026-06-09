#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

release_dir="release"
archive="$release_dir/trust-web.tar.gz"
checksum="$release_dir/trust-web.sha256"

rm -rf "$release_dir"
mkdir -p "$release_dir"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}"

tar \
  --sort=name \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --mtime="@$SOURCE_DATE_EPOCH" \
  -czf "$archive" \
  -C dist .

sha256sum "$archive" > "$checksum"

cat "$checksum"
