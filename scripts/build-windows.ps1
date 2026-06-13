param(
    [string]$Out = "ferrum.exe"
)

$ErrorActionPreference = "Stop"

$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"

Write-Host "[*] Building Ferrum for Windows x64..."
go build -trimpath -ldflags "-s -w" -o $Out ./cmd
Write-Host "[+] Built $Out"
