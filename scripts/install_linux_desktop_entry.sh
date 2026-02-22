#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-$HOME/.local}"
DESKTOP_DIR="${PREFIX}/share/applications"
ICON_DIR="${PREFIX}/share/icons/hicolor/scalable/apps"

mkdir -p "${DESKTOP_DIR}" "${ICON_DIR}"
install -m 0644 packaging/linux/sis.desktop "${DESKTOP_DIR}/sis.desktop"
install -m 0644 packaging/linux/icons/sis.svg "${ICON_DIR}/sis.svg"

echo "Installed desktop entry:"
echo "  ${DESKTOP_DIR}/sis.desktop"
echo "Installed icon:"
echo "  ${ICON_DIR}/sis.svg"
