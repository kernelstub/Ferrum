# Windows Package Layout

The `ferrum/windows/facade` package is the compatibility layer used by modules. The
implementation lives in real subpackages under this directory.

Modules import `ferrum/windows/facade`, while internal code is organized by Windows
research area. New low-level collectors should usually be added to the relevant
subpackage and re-exported from `facade/` only when modules need it.

The package is organized by Windows research area:

- `advanced/`: advanced scanner dispatcher, built-ins, profiles, and helpers.
- `audit/`: registry/policy/DLL-search audit collectors.
- `env/`, `pipes/`, `scheduled/`, `startup/`: focused collectors.
- `facade/`: module-facing compatibility API.
- `process/`: process enumeration and non-Windows stubs.
- `registry/`: registry helpers plus CLSID/COM registry enumeration.
- `services/`: Service Control Manager, service, and driver inventory.
- `token/`: access token, integrity, elevation, and privilege helpers.
- `types/`: grouped data models shared by modules.
