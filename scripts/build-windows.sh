#!/usr/bin/env sh
set -eu

OUT="${1:-ferrum.exe}"

echo "[*] Building Ferrum for Windows x64..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT" ./cmd
echo "[+] Built $OUT"
