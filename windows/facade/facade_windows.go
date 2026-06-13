//go:build windows

package facade

import (
	"ferrum/windows/advanced"
	"ferrum/windows/audit"
	winenv "ferrum/windows/env"
	"ferrum/windows/migrations"
	"ferrum/windows/pipes"
	winprocess "ferrum/windows/process"
	"ferrum/windows/registry"
	"ferrum/windows/scheduled"
	"ferrum/windows/services"
	"ferrum/windows/startup"
	"ferrum/windows/token"
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

func EnumerateProcesses() ([]Process, error)            { return winprocess.EnumerateProcesses() }
func InspectProcessToken(pid uint32) (TokenInfo, error) { return token.InspectProcessToken(pid) }
func EnumerateHKCUCLSID() ([]CLSIDEntry, error)         { return registry.EnumerateHKCUCLSID() }
func EnumerateCLSIDProcMonCandidates() ([]CLSIDProcMonCandidate, error) {
	return registry.EnumerateCLSIDProcMonCandidates()
}
func EnumerateServices() ([]ServiceInfo, error)         { return services.EnumerateServices() }
func EnumerateDrivers() ([]DriverInfo, error)           { return services.EnumerateDrivers() }
func EnumerateNamedPipes() ([]PipeInfo, error)          { return pipes.EnumerateNamedPipes() }
func EnumerateStartupEntries() ([]StartupEntry, error)  { return startup.EnumerateStartupEntries() }
func EnumerateScheduledTasks() ([]ScheduledTask, error) { return scheduled.EnumerateScheduledTasks() }
func EnumerateEnvironment() ([]EnvVar, error)           { return winenv.EnumerateEnvironment() }
func EnumerateProcessMitigations() ([]ProcessMitigation, error) {
	return migrations.EnumerateProcessMitigations()
}
func EnumerateRegistryAuditFindings() ([]RegistryAuditFinding, error) {
	return audit.EnumerateRegistryAuditFindings()
}
func EnumerateDLLSearchPathFindings() ([]DLLSearchPathFinding, error) {
	return audit.EnumerateDLLSearchPathFindings()
}
func EnumeratePolicyFindings() ([]PolicyFinding, error) { return audit.EnumeratePolicyFindings() }
func EnumerateAdvancedFindings(check string) ([]AdvancedFinding, error) {
	return advanced.EnumerateAdvancedFindings(check)
}
