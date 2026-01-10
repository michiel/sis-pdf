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
release_json="$(curl -fsSL -H "User-Agent: sis-install" "$api_url")" || {
  echo "Failed to query GitHub releases for $REPO" >&2
  exit 1
}
if [ -z "$release_json" ]; then
  echo "Empty response from GitHub releases API for $REPO" >&2
  exit 1
fi
if printf "%s" "$release_json" | grep -q "API rate limit exceeded"; then
  echo "Error: GitHub API rate limit exceeded. Try again later or use a GitHub token:" >&2
  echo "  export GITHUB_TOKEN=...   # then re-run the installer" >&2
  exit 1
fi

suffix="-$target.$ext"
read -r tag url <<EOF_META
$(printf "%s" "$release_json" | awk -v suffix="$suffix" '
  /"tag_name":/ {
    tag=$2
    gsub(/"|,/, "", tag)
  }
  /"draft":/ {
    draft=$2
    gsub(/,/, "", draft)
    skip=(draft=="true")
  }
  /"browser_download_url":/ {
    if (skip) { next }
    if ($0 ~ suffix && $0 ~ /sis-/) {
      url=$2
      gsub(/"|,/, "", url)
      print tag
      print url
      exit
    }
  }
')
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

if [ -n "${SIS_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$SIS_INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
elif [ -d "$HOME/.local/bin" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

install -m 755 "$tmpdir/$bin_name" "$INSTALL_DIR/$bin_name"

echo "Installed sis $tag to $INSTALL_DIR/$bin_name"
if ! command -v sis >/dev/null 2>&1; then
  echo "Add $INSTALL_DIR to your PATH to run sis" >&2
fi
