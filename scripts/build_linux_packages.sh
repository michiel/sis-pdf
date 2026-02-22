#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-dev}"
TARGET="${2:-x86_64-unknown-linux-gnu}"
OUT_DIR="${3:-dist/linux-packages}"
BIN_PATH="target/${TARGET}/release/sis-pdf-gui"
STAGING="$(mktemp -d)"
PREFIX_DIR="${STAGING}/usr"

cleanup() {
  rm -rf "${STAGING}"
}
trap cleanup EXIT

mkdir -p "${OUT_DIR}"

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "Building sis-pdf-gui for ${TARGET}..."
  cargo build --release -p sis-pdf-gui --target "${TARGET}"
fi

mkdir -p "${PREFIX_DIR}/bin"
mkdir -p "${PREFIX_DIR}/share/applications"
mkdir -p "${PREFIX_DIR}/share/icons/hicolor/scalable/apps"

install -m 0755 "${BIN_PATH}" "${PREFIX_DIR}/bin/sis-pdf-gui"
install -m 0644 packaging/linux/sis.desktop "${PREFIX_DIR}/share/applications/sis.desktop"
install -m 0644 packaging/linux/icons/sis.svg "${PREFIX_DIR}/share/icons/hicolor/scalable/apps/sis.svg"

if command -v fpm >/dev/null 2>&1; then
  echo "Building .deb and .rpm packages with fpm..."
  fpm -s dir -t deb -n sis-pdf-gui -v "${VERSION}" -C "${STAGING}" \
    --description "sis native PDF security GUI" \
    --license "MIT" \
    --maintainer "sis maintainers" \
    -p "${OUT_DIR}/sis-pdf-gui_${VERSION}_${TARGET}.deb" \
    usr
  fpm -s dir -t rpm -n sis-pdf-gui -v "${VERSION}" -C "${STAGING}" \
    --description "sis native PDF security GUI" \
    --license "MIT" \
    --maintainer "sis maintainers" \
    -p "${OUT_DIR}/sis-pdf-gui-${VERSION}.${TARGET}.rpm" \
    usr
else
  echo "Skipping .deb/.rpm packaging: fpm is not installed."
fi

if command -v appimagetool >/dev/null 2>&1; then
  echo "Building AppImage..."
  APPDIR="${STAGING}/AppDir"
  mkdir -p "${APPDIR}/usr/bin"
  mkdir -p "${APPDIR}/usr/share/applications"
  mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"
  install -m 0755 "${BIN_PATH}" "${APPDIR}/usr/bin/sis-pdf-gui"
  install -m 0644 packaging/linux/sis.desktop "${APPDIR}/usr/share/applications/sis.desktop"
  install -m 0644 packaging/linux/icons/sis.svg \
    "${APPDIR}/usr/share/icons/hicolor/scalable/apps/sis.svg"
  cat > "${APPDIR}/AppRun" <<'EOF'
#!/usr/bin/env bash
exec "${APPDIR}/usr/bin/sis-pdf-gui" "$@"
EOF
  chmod +x "${APPDIR}/AppRun"
  appimagetool "${APPDIR}" "${OUT_DIR}/sis-pdf-gui-${VERSION}-${TARGET}.AppImage"
else
  echo "Skipping AppImage packaging: appimagetool is not installed."
fi

echo "Packaging complete. Artefacts (if built) are in ${OUT_DIR}"
