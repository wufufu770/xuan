#!/usr/bin/env bash
# Chrome for Testing 引导下载：构建/运行前把发行包内引用的 Chrome
# 落到 tools/chrome-for-testing/（该目录不入 git——二进制超 GitHub 限制，
# 由本脚本按版本拉取官方 zip）。
set -euo pipefail

CHROME_VERSION="151.0.7922.34"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/tools/chrome-for-testing/$CHROME_VERSION"
URL="https://storage.googleapis.com/chrome-for-testing-public/$CHROME_VERSION/linux64/chrome-linux64.zip"

if [ -x "$DEST/chrome-linux64/chrome" ]; then
  echo "chrome already present: $DEST/chrome-linux64/chrome"
  exit 0
fi

echo "downloading Chrome for Testing $CHROME_VERSION ..."
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fL --retry 3 -o "$TMP/chrome.zip" "$URL"
unzip -q "$TMP/chrome.zip" -d "$DEST"
chmod +x "$DEST/chrome-linux64/chrome"
echo "installed: $DEST/chrome-linux64/chrome"
