#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-tmp/gui-smoke}"
SCREENSHOT_XWD="${OUT_DIR}/gui-smoke.xwd"
SCREENSHOT_PNG="${OUT_DIR}/gui-smoke.png"
LOG_FILE="${OUT_DIR}/gui-smoke.log"
WINDOW_INFO="${OUT_DIR}/xwininfo.txt"

mkdir -p "${OUT_DIR}"

if [[ "${SIS_GUI_SMOKE_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build -p sis-pdf-gui
fi

if ! command -v xvfb-run >/dev/null 2>&1; then
  echo "xvfb-run is required" >&2
  exit 2
fi
if ! command -v xwd >/dev/null 2>&1; then
  echo "xwd is required" >&2
  exit 2
fi
if ! command -v convert >/dev/null 2>&1; then
  echo "convert (ImageMagick) is required" >&2
  exit 2
fi
if ! command -v identify >/dev/null 2>&1; then
  echo "identify (ImageMagick) is required" >&2
  exit 2
fi

timeout --signal=TERM 45s xvfb-run -a -s "-screen 0 1280x800x24" bash -lc '
  set -euo pipefail
  OUT_DIR="'"${OUT_DIR}"'"
  LOG_FILE="'"${LOG_FILE}"'"
  WINDOW_INFO="'"${WINDOW_INFO}"'"
  SCREENSHOT_XWD="'"${SCREENSHOT_XWD}"'"
  SCREENSHOT_PNG="'"${SCREENSHOT_PNG}"'"

  MESA_LOADER_DRIVER_OVERRIDE=llvmpipe \
  LIBGL_ALWAYS_SOFTWARE=1 \
  ./target/debug/sis-pdf-gui >"${LOG_FILE}" 2>&1 &
  GUI_PID=$!

  for _ in $(seq 1 30); do
    if xwininfo -root >"${WINDOW_INFO}" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  # Give egui one more render interval after the display is ready.
  sleep 2

  xwd -root -silent >"${SCREENSHOT_XWD}"
  convert "${SCREENSHOT_XWD}" "${SCREENSHOT_PNG}"

  kill "${GUI_PID}" >/dev/null 2>&1 || true
  wait "${GUI_PID}" >/dev/null 2>&1 || true
'

if [[ ! -s "${SCREENSHOT_PNG}" ]]; then
  echo "screenshot missing or empty: ${SCREENSHOT_PNG}" >&2
  exit 10
fi

UNIQUE_COLOURS="$(identify -format "%k" "${SCREENSHOT_PNG}" 2>/dev/null || echo 0)"
if [[ "${UNIQUE_COLOURS}" -le 1 ]]; then
  echo "screenshot appears monochrome (${UNIQUE_COLOURS} colours)" >&2
  exit 10
fi

echo "GUI smoke screenshot captured: ${SCREENSHOT_PNG} (${UNIQUE_COLOURS} colours)"
