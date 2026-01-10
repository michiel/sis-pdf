#!/usr/bin/env sh
set -euo pipefail

REPO="${SIS_GITHUB_REPO:-michiel/sis-pdf}"
INSTALL_DIR="${SIS_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)
    if [ "$arch" != "x86_64" ]; then
      echo "Unsupported architecture: $arch" >&2
      exit 1
    fi
    target="x86_64-unknown-linux-gnu"
    ext="tar.gz"
    bin_name="sis"
    ;;
  Darwin)
    if [ "$arch" != "arm64" ]; then
      echo "Unsupported macOS architecture: $arch" >&2
      exit 1
    fi
    target="aarch64-apple-darwin"
    ext="tar.gz"
    bin_name="sis"
    ;;
  *)
    echo "Unsupported OS: $os" >&2
    exit 1
    ;;
esac

api_url="https://api.github.com/repos/$REPO/releases?per_page=20"
release_json="$(curl -fsSL -H "User-Agent: sis-install" "$api_url")"

export SIS_TARGET="$target"
export SIS_EXT="$ext"

read -r tag url <<EOF_META
$(printf "%s" "$release_json" | python3 - <<'PY'
import json
import os
import sys

data = json.load(sys.stdin)
suffix = f"-{os.environ['SIS_TARGET']}.{os.environ['SIS_EXT']}"

def iter_releases(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and "assets" in payload:
        return [payload]
    return []

for release in iter_releases(data):
    if release.get("draft"):
        continue
    for asset in release.get("assets", []):
        name = asset.get("name") or ""
        if name.startswith("sis-") and name.endswith(suffix):
            print(release.get("tag_name", ""))
            print(asset.get("browser_download_url", ""))
            sys.exit(0)
print("", file=sys.stderr)
sys.exit(1)
PY
)
EOF_META

if [ -z "$url" ]; then
  echo "No release asset found for $target" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

archive="$tmpdir/sis-$tag-$target.$ext"
curl -fsSL -H "User-Agent: sis-install" -o "$archive" "$url"

tar -C "$tmpdir" -xzf "$archive"

mkdir -p "$INSTALL_DIR"
install -m 755 "$tmpdir/$bin_name" "$INSTALL_DIR/$bin_name"

echo "Installed sis $tag to $INSTALL_DIR/$bin_name"
if ! command -v sis >/dev/null 2>&1; then
  echo "Add $INSTALL_DIR to your PATH to run sis" >&2
fi
