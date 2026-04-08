#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  verify-release-assets.sh --release-dir <dir> [--repo <owner/name> --bundle <path>]

Checks:
  - verifies SHA256SUMS against all listed files
  - optionally verifies GitHub provenance attestations for each shipped asset

Examples:
  verify-release-assets.sh --release-dir dist
  verify-release-assets.sh --release-dir dist --repo 777genius/lintai --bundle dist/lintai-v0.1.0-beta.1-provenance.intoto.jsonl
EOF
}

die() {
  echo "$*" >&2
  exit 1
}

release_dir=""
repo=""
bundle=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-dir)
      [[ $# -ge 2 ]] || die "--release-dir requires a value"
      release_dir="$2"
      shift 2
      ;;
    --repo)
      [[ $# -ge 2 ]] || die "--repo requires a value"
      repo="$2"
      shift 2
      ;;
    --bundle)
      [[ $# -ge 2 ]] || die "--bundle requires a value"
      bundle="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$release_dir" ]] || die "--release-dir is required"
[[ -d "$release_dir" ]] || die "release directory does not exist: $release_dir"

checksums_path="${release_dir%/}/SHA256SUMS"
[[ -f "$checksums_path" ]] || die "missing checksum manifest: $checksums_path"

(
  cd "$release_dir"
  sha256sum -c SHA256SUMS
)

if [[ -z "$repo" && -z "$bundle" ]]; then
  exit 0
fi

[[ -n "$repo" ]] || die "--repo is required when provenance verification is enabled"
[[ -n "$bundle" ]] || die "--bundle is required when provenance verification is enabled"
[[ -f "$bundle" ]] || die "provenance bundle does not exist: $bundle"

command -v gh >/dev/null 2>&1 || die "GitHub CLI 'gh' is required for provenance verification"

trusted_root="$(mktemp)"
trap 'rm -f "$trusted_root"' EXIT

gh attestation trusted-root > "$trusted_root"

while read -r _ file_name; do
  [[ -n "$file_name" ]] || continue
  gh attestation verify "${release_dir%/}/$file_name" \
    --repo "$repo" \
    --bundle "$bundle" \
    --custom-trusted-root "$trusted_root" >/dev/null
done < "$checksums_path"

echo "release assets and provenance verified for $release_dir"
