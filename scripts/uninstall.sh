#!/bin/sh

# sipr uninstaller (for installs made by scripts/install.sh)
# Usage: curl -fsSL https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/uninstall.sh | sh

set -e

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

setup_colors

BINARY_PATH=""
if command -v sipr >/dev/null 2>&1; then
    BINARY_PATH=$(command -v sipr)
elif [ -f "${HOME}/.local/bin/sipr" ]; then
    BINARY_PATH="${HOME}/.local/bin/sipr"
elif [ -f "/usr/local/bin/sipr" ]; then
    BINARY_PATH="/usr/local/bin/sipr"
fi
[ -n "${BINARY_PATH}" ] || error "sipr was not found on this system."

info "Found sipr at: ${BINARY_PATH}"

if [ -t 0 ] && [ -t 1 ]; then
    printf "Remove it? [y/N] "
    read -r ANSWER
    case "${ANSWER}" in
        [yY]|[yY][eE][sS]) ;;
        *) info "Uninstall cancelled."; exit 0 ;;
    esac
fi

if rm "${BINARY_PATH}" 2>/dev/null; then
    success "sipr has been uninstalled."
else
    warn "Permission denied; retrying with sudo..."
    sudo rm "${BINARY_PATH}" && success "sipr has been uninstalled." || error "Failed to remove ${BINARY_PATH}."
fi
