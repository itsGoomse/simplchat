#!/usr/bin/env bash
#
# install-systemd.sh — Install simplchat-server as a systemd service.
#
# This copies the service template, substitutes the correct user and project
# paths, and enables/starts the service so the relay server runs in the
# background and auto-starts on boot.
#
# Usage:
#   ./install-systemd.sh
#   ./install-systemd.sh --uninstall   # remove the service
#

set -euo pipefail

# --- Colours (only when stdout is a TTY) -------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'
    C_RED=$'\033[31m'
else
    C_RESET=""
    C_GREEN=""
    C_YELLOW=""
    C_CYAN=""
    C_RED=""
fi

info()  { printf '%s[INFO]%s %s\n'  "$C_CYAN"   "$C_RESET" "$*"; }
ok()    { printf '%s[ OK ]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*"; }
die()   { printf '%s[FAIL]%s %s\n'  "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

# --- Locate the script's directory ------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Uninstall mode ----------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
    info "Stopping and removing the simplchat-server service..."
    systemctl stop simplchat-server 2>/dev/null || true
    systemctl disable simplchat-server 2>/dev/null || true
    rm -f /etc/systemd/system/simplchat-server.service
    systemctl daemon-reload
    ok "Service removed."
    exit 0
fi

# --- Check for systemd -------------------------------------------------------
if ! command -v systemctl >/dev/null 2>&1; then
    die "systemd not found. This script is for systems using systemd."
fi

# --- Substitute placeholders -------------------------------------------------
USER_NAME="$(id -un)"
PROJECT_DIR="$SCRIPT_DIR"

info "Installing simplchat-server as a systemd service..."
info "  User:        $USER_NAME"
info "  Project dir: $PROJECT_DIR"

# Copy the template and replace the placeholders.
sed -e "s|__USER__|$USER_NAME|g" \
    -e "s|__PROJECT_DIR__|$PROJECT_DIR|g" \
    simplchat-server.service > /etc/systemd/system/simplchat-server.service

# --- Enable and start --------------------------------------------------------
systemctl daemon-reload
systemctl enable simplchat-server
systemctl start simplchat-server

ok "Service installed and started."
info "Check status with: systemctl status simplchat-server"
info "View logs with:    journalctl -u simplchat-server -f"
