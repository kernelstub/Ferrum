//go:build !windows

package facade

import (
	"runtime"

	winerrors "ferrum/windows/errors"
	winprocess "ferrum/windows/process"
	"ferrum/windows/registry"
	wintypes "ferrum/windows/types"
)

type Process = winprocess.Process
type ProcessMitigation = winprocess.ProcessMitigation
type TokenInfo = wintypes.TokenInfo
type PolicyFinding = wintypes.PolicyFinding
type CLSIDEntry = registry.CLSIDEntry
type CLSIDProcMonCandidate = registry.CLSIDProcMonCandidate
type RegistryAuditFinding = registry.RegistryAuditFinding
type DLLSearchPathFinding = wintypes.DLLSearchPathFinding
type AdvancedFinding = wintypes.AdvancedFinding
type ServiceInfo = wintypes.ServiceInfo
type DriverInfo = wintypes.DriverInfo
type PipeInfo = wintypes.PipeInfo
type StartupEntry = wintypes.StartupEntry
type ScheduledTask = wintypes.ScheduledTask
type EnvVar = wintypes.EnvVar

func unsupported() error { return winerrors.ErrUnsupported(runtime.GOOS) }

func EnumerateProcesses() ([]Process, error)                            { return nil, unsupported() }
func InspectProcessToken(pid uint32) (TokenInfo, error)                 { return TokenInfo{}, unsupported() }
func EnumerateHKCUCLSID() ([]CLSIDEntry, error)                         { return nil, unsupported() }
func EnumerateCLSIDProcMonCandidates() ([]CLSIDProcMonCandidate, error) { return nil, unsupported() }
func EnumerateServices() ([]ServiceInfo, error)                         { return nil, unsupported() }
func EnumerateDrivers() ([]DriverInfo, error)                           { return nil, unsupported() }
func EnumerateNamedPipes() ([]PipeInfo, error)                          { return nil, unsupported() }
func EnumerateStartupEntries() ([]StartupEntry, error)                  { return nil, unsupported() }
func EnumerateScheduledTasks() ([]ScheduledTask, error)                 { return nil, unsupported() }
func EnumerateEnvironment() ([]EnvVar, error)                           { return nil, unsupported() }
func EnumerateProcessMitigations() ([]ProcessMitigation, error)         { return nil, unsupported() }
func EnumerateRegistryAuditFindings() ([]RegistryAuditFinding, error)   { return nil, unsupported() }
func EnumerateDLLSearchPathFindings() ([]DLLSearchPathFinding, error)   { return nil, unsupported() }
func EnumeratePolicyFindings() ([]PolicyFinding, error)                 { return nil, unsupported() }
func EnumerateAdvancedFindings(check string) ([]AdvancedFinding, error) { return nil, unsupported() }
