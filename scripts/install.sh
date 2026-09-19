#!/bin/sh

# sipr installer
# Supported platforms: macOS (x86_64, arm64), Linux (x86_64, arm64; static musl binaries)
# Usage: curl -fsSL https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/install.sh | sh
#   VERSION=v0.26.0 ...   install a specific release instead of the latest
#   GITHUB_TOKEN=...      authenticate GitHub requests (rate limits, private forks)

set -eu

REPO_OWNER="tareqmy"
REPO_NAME="sipr"
GITHUB_RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/master"
GITHUB_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
GITHUB_RELEASES_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"

setup_colors() {
    if [ -t 1 ]; then
        RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
    else
        RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
    fi
}

info()    { printf "${BLUE}[info]${NC} %s\n" "$1"; }
success() { printf "${GREEN}[success]${NC} %s\n" "$1"; }
warn()    { printf "${YELLOW}[warn]${NC} %s\n" "$1"; }
error()   { printf "${RED}[error]${NC} %s\n" "$1" >&2; exit 1; }

# Fetch a URL to stdout with curl or wget, honoring GITHUB_TOKEN.
fetch() {
    if command -v curl >/dev/null 2>&1; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" "$1"
        else
            curl -fsSL "$1"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            wget -qO- --header="Authorization: token ${GITHUB_TOKEN}" "$1"
        else
            wget -qO- "$1"
        fi
    else
        error "Neither curl nor wget found."
    fi
}

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    case "${OS}" in
        Darwin)
            case "${ARCH}" in
                x86_64) TARGET="x86_64-apple-darwin" ;;
                arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
                *) error "Unsupported macOS architecture: ${ARCH}" ;;
            esac
            ;;
        Linux)
            case "${ARCH}" in
                x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
                arm64|aarch64) TARGET="aarch64-unknown-linux-musl" ;;
                *) error "Unsupported Linux architecture: ${ARCH}" ;;
            esac
            ;;
        *)
            error "Unsupported operating system: ${OS} (on Windows use scripts/install.ps1)"
            ;;
    esac
    info "Detected platform: ${OS} (${ARCH}) -> ${TARGET}"
}

# Reject an error document that a fetch returned instead of a version.
looks_like_version() {
    echo "$1" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+'
}

resolve_version() {
    if [ -z "${VERSION:-}" ]; then
        info "Querying latest version..."
        LATEST=""
        # A local checkout carries the version in .version.
        if [ -f ".version" ] && [ -d ".git" ] && grep -q '^name = "sipr"' Cargo.toml 2>/dev/null; then
            LATEST=$(cat .version)
            info "Found local .version: ${LATEST}"
        fi
        if [ -z "${LATEST}" ]; then
            LATEST=$(fetch "${GITHUB_RAW_URL}/.version" 2>/dev/null || true)
        fi
        if ! looks_like_version "${LATEST:-}"; then
            info "Falling back to the GitHub releases API..."
            JSON=$(fetch "${GITHUB_API_URL}/releases/latest" 2>/dev/null || true)
            LATEST=$(echo "${JSON}" | grep '"tag_name":' | head -n 1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)
        fi
        if ! looks_like_version "${LATEST:-}"; then
            error "Could not determine the latest version (network issue or GitHub rate limit). Pass one explicitly: VERSION=v0.26.0 sh install.sh"
        fi
        VERSION="${LATEST}"
    fi
    case "${VERSION}" in
        v*) ;;
        *) VERSION="v${VERSION}" ;;
    esac
    info "Using version: ${VERSION}"
}

select_install_dir() {
    if [ "$(id -u)" -eq 0 ] || [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
        mkdir -p "${INSTALL_DIR}"
    fi
    info "Installing into: ${INSTALL_DIR}"
}

download_and_extract() {
    ASSET_NAME="sipr-${VERSION}-${TARGET}.tar.gz"
    DOWNLOAD_URL="${GITHUB_RELEASES_URL}/download/${VERSION}/${ASSET_NAME}"

    TMP_DIR=$(mktemp -d -t sipr-install.XXXXXX)
    trap 'rm -rf "${TMP_DIR}"' EXIT INT TERM
    ARCHIVE_PATH="${TMP_DIR}/${ASSET_NAME}"

    if [ -n "${GITHUB_TOKEN:-}" ]; then
        # Authenticated download goes through the assets API.
        RELEASE_JSON=$(fetch "${GITHUB_API_URL}/releases/tags/${VERSION}") || error "Failed to read release ${VERSION}."
        ASSET_ID=$(echo "${RELEASE_JSON}" | grep -B 10 -A 10 "\"name\": \"${ASSET_NAME}\"" | grep '"id":' | head -n 1 | sed -E 's/.*"id": *([0-9]+).*/\1/' || true)
        [ -n "${ASSET_ID}" ] || error "Release ${VERSION} has no asset named ${ASSET_NAME}."
        info "Downloading ${ASSET_NAME} (asset ${ASSET_ID})..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" -H "Accept: application/octet-stream" \
                -o "${ARCHIVE_PATH}" "${GITHUB_API_URL}/releases/assets/${ASSET_ID}"
        else
            wget -q -O "${ARCHIVE_PATH}" --header="Authorization: token ${GITHUB_TOKEN}" \
                --header="Accept: application/octet-stream" "${GITHUB_API_URL}/releases/assets/${ASSET_ID}"
        fi
    else
        info "Downloading ${DOWNLOAD_URL}"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL -o "${ARCHIVE_PATH}" "${DOWNLOAD_URL}"
        else
            wget -q -O "${ARCHIVE_PATH}" "${DOWNLOAD_URL}"
        fi
    fi

    info "Extracting..."
    tar -xzf "${ARCHIVE_PATH}" -C "${TMP_DIR}"
    BINARY_PATH=$(find "${TMP_DIR}" -type f -name sipr -print -quit || true)
    [ -n "${BINARY_PATH}" ] && [ -f "${BINARY_PATH}" ] || error "Binary 'sipr' not found in ${ASSET_NAME}."

    info "Installing sipr to ${INSTALL_DIR}..."
    mv "${BINARY_PATH}" "${INSTALL_DIR}/sipr"
    chmod +x "${INSTALL_DIR}/sipr"
}

verify_path() {
    case ":${PATH}:" in
        *:"${INSTALL_DIR}":*)
            success "sipr is installed and on your PATH."
            ;;
        *)
            warn "${INSTALL_DIR} is not on your PATH. Add it in your shell profile (.zshrc, .bashrc, or .profile):"
            printf "\n  export PATH=\"\$PATH:%s\"\n\n" "${INSTALL_DIR}"
            ;;
    esac
}

setup_colors
detect_platform
resolve_version
select_install_dir
download_and_extract
verify_path

if VERSION_OUT=$("${INSTALL_DIR}/sipr" --version 2>&1); then
    success "Installed: ${VERSION_OUT}"
else
    warn "The installed binary could not be run: ${VERSION_OUT}"
fi
