#!/bin/sh
set -eu

RELEASE_TAG="${LINTAI_INSTALL_RELEASE_TAG:-__RELEASE_TAG__}"
RELEASE_REPOSITORY="${LINTAI_INSTALL_RELEASE_REPOSITORY:-__RELEASE_REPOSITORY__}"
DEFAULT_INSTALL_DIR="${HOME}/.local/bin"
DEFAULT_BASE_URL="https://github.com/${RELEASE_REPOSITORY}/releases/download/${RELEASE_TAG}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '%s\n' "$*"
}

usage() {
  cat <<'EOF'
lintai installer

Usage:
  sh ./lintai-installer.sh [--target <triple>] [--install-dir <dir>] [--base-url <url>]

Options:
  --target <triple>       Override target detection.
  --install-dir <dir>     Install directory. Default: ~/.local/bin
  --base-url <url>        Override asset base URL. Primarily for smoke tests.
  --help                  Show this help.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

checksum_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  die "missing required checksum tool: sha256sum or shasum"
}

detect_target() {
  os_name="$(uname -s 2>/dev/null || true)"
  arch_name="$(uname -m 2>/dev/null || true)"

  case "$os_name" in
    Linux)
      case "$arch_name" in
        x86_64|amd64)
          if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
            printf 'x86_64-unknown-linux-musl\n'
          else
            printf 'x86_64-unknown-linux-gnu\n'
          fi
          ;;
        *)
          die "unsupported Linux architecture: $arch_name"
          ;;
      esac
      ;;
    Darwin)
      case "$arch_name" in
        arm64|aarch64)
          printf 'aarch64-apple-darwin\n'
          ;;
        *)
          die "unsupported macOS architecture: $arch_name (supported: arm64)"
          ;;
      esac
      ;;
    *)
      die "unsupported operating system: $os_name"
      ;;
  esac
}

INSTALL_DIR="$DEFAULT_INSTALL_DIR"
TARGET=""
BASE_URL="${LINTAI_INSTALL_BASE_URL:-$DEFAULT_BASE_URL}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      [ "$#" -ge 2 ] || die "missing value for --target"
      TARGET="$2"
      shift 2
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || die "missing value for --install-dir"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --base-url)
      [ "$#" -ge 2 ] || die "missing value for --base-url"
      BASE_URL="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

case "$RELEASE_TAG" in
  *__RELEASE_TAG__*|"" )
    die "this installer is a template; download lintai-installer.sh from a published GitHub Release asset"
    ;;
esac

case "$RELEASE_REPOSITORY" in
  *__RELEASE_REPOSITORY__*|"" )
    die "this installer is a template; download lintai-installer.sh from a published GitHub Release asset"
    ;;
esac

require_command curl
require_command tar

if [ -z "$TARGET" ]; then
  TARGET="$(detect_target)"
fi

case "$TARGET" in
  x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl|aarch64-apple-darwin) ;;
  *)
    die "unsupported target: $TARGET"
    ;;
esac

ASSET_BASENAME="lintai-${RELEASE_TAG}-${TARGET}"
ARCHIVE_NAME="${ASSET_BASENAME}.tar.gz"
CHECKSUM_NAME="SHA256SUMS"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT HUP TERM

info "Downloading ${ARCHIVE_NAME} from ${BASE_URL}"
curl -fsSL -o "${TMP_DIR}/${ARCHIVE_NAME}" "${BASE_URL}/${ARCHIVE_NAME}"
curl -fsSL -o "${TMP_DIR}/${CHECKSUM_NAME}" "${BASE_URL}/${CHECKSUM_NAME}"

EXPECTED_SUM="$(awk -v asset="$ARCHIVE_NAME" '$2 == asset { print $1 }' "${TMP_DIR}/${CHECKSUM_NAME}" | head -n 1)"
[ -n "$EXPECTED_SUM" ] || die "checksum for ${ARCHIVE_NAME} not found in ${CHECKSUM_NAME}"
ACTUAL_SUM="$(checksum_file "${TMP_DIR}/${ARCHIVE_NAME}")"
[ "$EXPECTED_SUM" = "$ACTUAL_SUM" ] || die "checksum mismatch for ${ARCHIVE_NAME}"

mkdir -p "$INSTALL_DIR"
tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "$TMP_DIR"
cp "${TMP_DIR}/${ASSET_BASENAME}/lintai" "${INSTALL_DIR}/lintai"
chmod 755 "${INSTALL_DIR}/lintai"

"${INSTALL_DIR}/lintai" help >/dev/null 2>&1 || die "installed binary failed smoke check: lintai help"

info "Installed lintai to ${INSTALL_DIR}/lintai"
case ":${PATH:-}:" in
  *:"${INSTALL_DIR}":*)
    info "lintai is already on PATH."
    ;;
  *)
    info "Add ${INSTALL_DIR} to PATH, then open a new shell."
    info "Example: export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
info "Verify with: lintai help"
