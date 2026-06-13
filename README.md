# FERRUM

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/924c39a5-5f9d-44b1-b9a3-ecd424140408" />


Ferrum is a Windows-first vulnerability research and security auditing framework written in Go. It is designed as a single binary, `ferrum.exe`, with modules registered through a small core interface.

## Build

```sh
GOOS=windows GOARCH=amd64 go build -o ferrum.exe ./cmd
```

Or use the included script:

```powershell
.\scripts\build-windows.ps1
```

From Linux/macOS:

```sh
./scripts/build-windows.sh
```

## Usage

```cmd
ferrum.exe --HELP
ferrum.exe --ALL --VERBOSE
ferrum.exe --ALL --OUTPUT ferrum-reports
ferrum.exe --CLSID
ferrum.exe --CLSID --OUTPUT clsid.txt
ferrum.exe --TOKENS
ferrum.exe --REGISTRY
ferrum.exe --POLICY
ferrum.exe --DLLSEARCH
ferrum.exe --SERVICES
ferrum.exe --DRIVERS
ferrum.exe --PIPES
ferrum.exe --STARTUP
ferrum.exe --SCHEDULED
ferrum.exe --ENV
ferrum.exe --MITIGATIONS
ferrum.exe --AUTORUNS
ferrum.exe --IFEO
ferrum.exe --SILENTEXIT
ferrum.exe --WINLOGON
ferrum.exe --LSA
ferrum.exe --APPINIT
ferrum.exe --APPCERT
ferrum.exe --UAC
ferrum.exe --INSTALLER
ferrum.exe --POWERSHELL
ferrum.exe --APPLOCKER
ferrum.exe --WDAC
ferrum.exe --DEFENDER
ferrum.exe --FIREWALL
ferrum.exe --RDP
ferrum.exe --WMI
ferrum.exe --HOSTS
ferrum.exe --SHARES
ferrum.exe --SHELL
ferrum.exe --BROWSER
ferrum.exe --PROTOCOLS
ferrum.exe --COMLOCAL
ferrum.exe --KNOWNDLLS
ferrum.exe --SVCPATHS
ferrum.exe --DRIVERPATHS
ferrum.exe --CERTIFICATES
ferrum.exe --NETWORKPROVIDERS
ferrum.exe --PRINT
ferrum.exe --WINSOCK
ferrum.exe --ACCESSIBILITY
ferrum.exe --CLSID --VERBOSE
ferrum.exe --CLSID --QUIET
```

## Architecture

- `cmd/` contains the CLI entry point.
- `core/` contains module registration, context, and banner code.
- `modules/` contains research modules. New modules implement `core.Module` and call `core.Register`.
- `windows/` contains build-tagged Windows API wrappers and non-Windows stubs.
- `output/` contains console logging.

## Output

Write a single module report:

```cmd
ferrum.exe --CLSID --OUTPUT clsid.txt
```

Run every module and write one file per module:

```cmd
ferrum.exe --ALL
ferrum.exe --ALL --OUTPUT ferrum-reports
```

Without `--OUTPUT`, `--ALL` creates a timestamped folder such as `ferrum-output-20260613-153000`.

## CLSID ProcMon Filter Model

`--CLSID` models this ProcMon workflow for COM hijack/LPE triage:

- `User is NT AUTHORITY\SYSTEM`
- `Path contains HKCU\Software\Classes`
- `Path contains InprocServer32`
- `Path contains LocalServer32`
- `Result is NAME NOT FOUND`
