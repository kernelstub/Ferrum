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
