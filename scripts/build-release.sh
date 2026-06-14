#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

release_dir="release"
archive="$release_dir/trust-web.tar.gz"
checksum="$release_dir/trust-web.sha256"
manifest="$release_dir/trust-web.release.json"

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

(
  cd "$release_dir"
  sha256sum trust-web.tar.gz > trust-web.sha256
)

archive_sha256="$(cut -d ' ' -f 1 "$checksum")"
commit="$(git rev-parse HEAD)"
cat > "$manifest" <<JSON
{
  "name": "trust-web",
  "commit": "$commit",
  "archive": "trust-web.tar.gz",
  "archive_sha256": "$archive_sha256",
  "source_date_epoch": "$SOURCE_DATE_EPOCH"
}
JSON

(
  cd "$release_dir"
  sha256sum trust-web.release.json >> trust-web.sha256
)

cat "$checksum"
