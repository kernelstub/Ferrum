//go:build windows

package advanced

import (
	"fmt"
	"os"
	"strings"

	winprocess "ferrum/windows/process"
	"ferrum/windows/registry"
	"ferrum/windows/services"
)

type surfaceProfile struct {
	area      string
	severity  string
	reason    string
	registry  []registryProbe
	globs     []string
	services  []string
	processes []string
}

type registryProbe struct {
	scope uintptr
	root  string
	path  string
}

func genericSurfaceFindings(check string) []AdvancedFinding {
	profile, ok := surfaceProfiles()[check]
	if !ok {
		return []AdvancedFinding{{
			Area:     strings.ToUpper(check),
			Target:   check,
			Severity: "Info",
			Reason:   "registered research surface; add a specialized collector for deeper enumeration",
		}}
	}

	findings := []AdvancedFinding{}
	for _, probe := range profile.registry {
		findings = append(findings, registryAllValues(profile.area, probe.scope, probe.root, probe.path, profile.severity, profile.reason)...)
		findings = append(findings, registrySubkeys(profile.area, probe.scope, probe.root, probe.path, profile.severity, profile.reason)...)
	}
	for _, pattern := range profile.globs {
		findings = append(findings, fileGlobFindings(profile.area, expandEnvPath(pattern), profile.severity, profile.reason)...)
	}
	if len(profile.services) > 0 {
		findings = append(findings, servicesMatching(profile.area, profile.services, profile.severity, profile.reason)...)
	}
	if len(profile.processes) > 0 {
		findings = append(findings, processesMatching(profile.area, profile.processes, profile.severity, profile.reason)...)
	}
	if len(findings) == 0 {
		findings = append(findings, AdvancedFinding{
			Area:     profile.area,
			Target:   check,
			Severity: "Info",
			Reason:   "no concrete artifacts found; surface remains registered for targeted research",
		})
	}
	return findings
}

func surfaceProfiles() map[string]surfaceProfile {
	return map[string]surfaceProfile{
		"comdcom":             registryProfile("COM/DCOM", "Medium", "COM/DCOM registration or security surface", []string{`Software\Classes\AppID`, `Software\Classes\CLSID`, `SOFTWARE\Classes\AppID`, `SOFTWARE\Classes\CLSID`}),
		"comelevation":        registryProfile("COM Elevation", "High", "COM elevation or auto-approval surface", []string{`SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList`, `Software\Classes\CLSID`}),
		"dcomactivation":      registryProfile("DCOM Activation", "Medium", "DCOM machine activation/security policy", []string{`SOFTWARE\Microsoft\Ole`, `Software\Classes\AppID`}),
		"rpc":                 serviceProfile("RPC", "Medium", "RPC-capable service or endpoint surface", []string{"rpc", "RpcSs", "RpcEptMapper", "DcomLaunch"}),
		"alpc":                mixedProfile("ALPC", "Info", "ALPC broker or object namespace surface", []string{`SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId`}, nil, []string{"runtimebroker", "dllhost", "svchost"}),
		"lpc":                 mixedProfile("LPC", "Info", "LPC/NT object boundary surface", []string{`SYSTEM\CurrentControlSet\Control\Session Manager`}, nil, []string{"csrss", "lsass", "winlogon"}),
		"tokenimpersonation":  serviceProfile("Token Impersonation", "High", "service process commonly relevant to impersonation research", []string{"RpcSs", "Spooler", "Schedule", "BITS", "WinRM", "WebClient"}),
		"uacautoelevation":    registryProfile("UAC Auto-Elevation", "High", "UAC auto-elevation approval or consent surface", []string{`SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`}),
		"msi":                 registryProfile("MSI", "High", "Windows Installer policy or product registration surface", []string{`Software\Policies\Microsoft\Windows\Installer`, `SOFTWARE\Policies\Microsoft\Windows\Installer`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Installer`}),
		"installerrepair":     registryProfile("Installer Repair", "Medium", "installer repair and advertised product surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData`, `SOFTWARE\Classes\Installer\Products`}),
		"wdacpolicy":          registryProfile("WDAC/AppLocker Interfaces", "Info", "application control policy interface", []string{`SYSTEM\CurrentControlSet\Control\CI\Policy`, `SOFTWARE\Policies\Microsoft\Windows\SrpV2`}),
		"brokers":             mixedProfile("Broker Processes", "Medium", "privileged broker process or COM broker surface", []string{`SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId`}, nil, []string{"runtimebroker", "dllhost", "consent", "appinfo"}),
		"appcontainerbrokers": mixedProfile("AppContainer Brokers", "Medium", "AppContainer capability or broker surface", []string{`SOFTWARE\Microsoft\SecurityManager\CapabilityClasses`, `SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer`}, nil, []string{"runtimebroker", "applicationframehost"}),
		"urlmonikers":         registryProfile("URL Monikers", "Medium", "URL protocol or moniker activation surface", []string{`Software\Classes`, `SOFTWARE\Classes`}),
		"comhijack":           registryProfile("COM Hijacking", "High", "per-user or machine COM registration hijack surface", []string{`Software\Classes\CLSID`, `Software\Classes\AppID`, `SOFTWARE\Classes\CLSID`}),
		"custommarshal":       registryProfile("Custom Marshaling", "High", "COM custom marshaling registration surface", []string{`Software\Classes\Interface`, `SOFTWARE\Classes\Interface`}),
		"dllhijacking":        mixedProfile("DLL Hijacking", "High", "DLL search or writable path surface", []string{`SYSTEM\CurrentControlSet\Control\Session Manager`, `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`}, []string{`%WINDIR%\System32\*.local`, `%ProgramData%\*.dll`}, nil),
		"sxs":                 mixedProfile("SxS", "Medium", "side-by-side assembly or manifest surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide`}, []string{`%WINDIR%\WinSxS\Manifests\*.manifest`, `%ProgramFiles%\*\*.manifest`}, nil),
		"activationctx":       mixedProfile("Activation Context", "Medium", "manifest activation context surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide`}, []string{`%ProgramFiles%\*\*.manifest`, `%ProgramFiles(x86)%\*\*.manifest`}, nil),
		"ntobjmgr":            registryProfile("NT Object Manager", "Info", "object namespace-related session manager surface", []string{`SYSTEM\CurrentControlSet\Control\Session Manager`, `SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices`}),
		"objdirs":             registryProfile("Object Directories", "Info", "object directory namespace indicator", []string{`SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices`}),
		"symlinks":            registryProfile("Symbolic Links", "Medium", "DOS device symbolic link surface", []string{`SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices`}),
		"hardlinks":           fileProfile("Hard Links", "Info", "hard-link-prone writable area for manual race research", []string{`%TEMP%\*`, `%ProgramData%\*`}),
		"junctions":           fileProfile("Junctions", "Medium", "junction-prone directory surface", []string{`%TEMP%\*`, `%ProgramData%\*`}),
		"mountpoints":         registryProfile("Mount Points", "Medium", "mounted device and mount manager surface", []string{`SYSTEM\MountedDevices`, `SYSTEM\CurrentControlSet\Services\mountmgr`}),
		"reparsepoints":       fileProfile("Reparse Points", "Medium", "reparse-point-prone writable area", []string{`%TEMP%\*`, `%ProgramData%\*`}),
		"oplocks":             fileProfile("OpLocks", "Info", "oplock/race-prone writable area", []string{`%TEMP%\*`, `%ProgramData%\*`}),
		"regsymlinks":         registryProfile("Registry Symlinks", "Medium", "registry link or virtualization-related surface", []string{`Software\Classes\VirtualStore`, `SOFTWARE\Classes\VirtualStore`}),
		"scm":                 serviceProfile("SCM", "Medium", "service control manager service configuration surface", []string{""}),
		"minifilters":         serviceProfile("Minifilters", "Medium", "file system minifilter driver surface", []string{"FltMgr", "WdFilter", "FileInfo", "luafv"}),
		"ioctls":              serviceProfile("IOCTLs", "High", "kernel driver device control surface", []string{"driver", "filter", "kbd", "mou", "disk", "ndis"}),
		"deviceobjects":       registryProfile("Device Objects", "Medium", "device class and driver object surface", []string{`SYSTEM\CurrentControlSet\Enum`, `SYSTEM\CurrentControlSet\Control\Class`}),
		"etw":                 registryProfile("ETW", "Info", "ETW provider registration surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`, `SOFTWARE\Microsoft\Windows\CurrentVersion\ETW`}),
		"win32k":              mixedProfile("Win32k", "Medium", "GUI subsystem boundary surface", []string{`SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems`}, nil, []string{"dwm", "winlogon", "csrss"}),
		"csrss":               mixedProfile("CSRSS", "High", "client/server runtime subsystem boundary", []string{`SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems`}, nil, []string{"csrss"}),
		"lsassinterfaces":     registryProfile("LSASS Interfaces", "High", "LSASS authentication and security package surface", []string{`SYSTEM\CurrentControlSet\Control\Lsa`, `SYSTEM\CurrentControlSet\Control\SecurityProviders`}),
		"accesstokens":        serviceProfile("Access Tokens", "High", "privileged service token surface", []string{"RpcSs", "Schedule", "Spooler", "WinRM", "BITS"}),
		"handles":             mixedProfile("Handles", "Info", "handle duplication/leak research target", nil, nil, []string{"lsass", "csrss", "services", "winlogon", "spoolsv"}),
		"jobobjects":          mixedProfile("Job Objects", "Info", "process containment and job object research target", nil, nil, []string{"svchost", "runtimebroker", "dllhost"}),
		"sectionobjects":      mixedProfile("Section Objects", "Info", "section object and image mapping research target", nil, []string{`%TEMP%\*.tmp`, `%ProgramData%\*.tmp`}, []string{"csrss", "lsass", "services"}),
		"sharedmemory":        mixedProfile("Shared Memory", "Info", "shared memory IPC research target", nil, []string{`%TEMP%\*`}, []string{"explorer", "runtimebroker", "dwm"}),
		"mmap":                fileProfile("Memory-Mapped Files", "Info", "memory-mapped file candidate", []string{`%TEMP%\*`, `%ProgramData%\*`}),
		"wfp":                 registryProfile("WFP", "Medium", "Windows Filtering Platform provider surface", []string{`SYSTEM\CurrentControlSet\Services\BFE`, `SYSTEM\CurrentControlSet\Services\SharedAccess`}),
		"hyperv":              serviceProfile("Hyper-V", "Medium", "Hyper-V component service surface", []string{"vmms", "vmcompute", "vmicheartbeat", "HvHost", "hns"}),
		"wsl":                 serviceProfile("WSL", "Medium", "Windows Subsystem for Linux component surface", []string{"LxssManager", "vmcompute", "hns"}),
		"efsrpc":              serviceProfile("EFSRPC", "High", "Encrypting File System RPC surface", []string{"EFS", "EFSRPC"}),
		"taskrpc":             serviceProfile("Task Scheduler RPC", "Medium", "Task Scheduler service RPC surface", []string{"Schedule"}),
		"bits":                serviceProfile("BITS", "Medium", "Background Intelligent Transfer Service surface", []string{"BITS"}),
		"endpointmapper":      serviceProfile("Endpoint Mapper", "Medium", "RPC Endpoint Mapper and DCOM launch surface", []string{"RpcEptMapper", "RpcSs", "DcomLaunch"}),
		"winrm":               serviceProfile("WinRM", "Medium", "Windows Remote Management service surface", []string{"WinRM"}),
		"smbipc":              serviceProfile("SMB Local IPC", "Medium", "SMB and IPC service surface", []string{"LanmanServer", "LanmanWorkstation", "srv2"}),
		"credproviders":       registryProfile("Credential Providers", "High", "credential provider registration surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters`}),
		"authpackages":        registryProfile("Authentication Packages", "High", "authentication package registration surface", []string{`SYSTEM\CurrentControlSet\Control\Lsa`}),
		"lsaplugins":          registryProfile("LSA Plugins", "High", "LSA plugin and notification package surface", []string{`SYSTEM\CurrentControlSet\Control\Lsa`, `SYSTEM\CurrentControlSet\Control\SecurityProviders`}),
		"cloudap":             registryProfile("CloudAP", "High", "cloud authentication package surface", []string{`SYSTEM\CurrentControlSet\Control\Lsa`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication`}),
		"ppl":                 registryProfile("PPL", "High", "Protected Process Light policy indicator", []string{`SYSTEM\CurrentControlSet\Control\Lsa`, `SYSTEM\CurrentControlSet\Control\CI`}),
		"userprofilesvc":      serviceProfile("User Profile Service", "Medium", "profile service and profile path surface", []string{"ProfSvc"}),
		"updates":             serviceProfile("Update Mechanisms", "Medium", "update service or repair/update mechanism surface", []string{"wuauserv", "UsoSvc", "BITS", "TrustedInstaller", "WaaSMedicSvc"}),
		"recovery":            registryProfile("Recovery", "Medium", "repair and recovery mechanism surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, `SYSTEM\Setup`}),
		"tempfiles":           fileProfile("Temporary Files", "Medium", "temporary file handling surface", []string{`%TEMP%\*`, `%TMP%\*`, `%WINDIR%\Temp\*`}),
		"toctou":              fileProfile("TOCTOU", "Medium", "race-prone writable filesystem surface", []string{`%TEMP%\*`, `%ProgramData%\*`, `%WINDIR%\Temp\*`}),
		"pathcanon":           fileProfile("Path Canonicalization", "Medium", "path parsing and canonicalization research surface", []string{`%TEMP%\*`, `%ProgramData%\*`}),
		"confuseddeputy":      serviceProfile("Confused Deputy", "Medium", "privileged service that may act on caller-controlled paths", []string{"Spooler", "Schedule", "BITS", "msiserver", "TrustedInstaller", "WinRM"}),
		"acl":                 mixedProfile("ACL Misconfigurations", "High", "path commonly worth ACL review", nil, []string{`%ProgramData%\*`, `%WINDIR%\Temp\*`}, nil),
		"envinjection":        registryProfile("Environment Injection", "Medium", "environment variable injection surface", []string{`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, `Environment`}),
		"searchpoison":        registryProfile("Search Path Poisoning", "High", "search path or App Paths poisoning surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths`, `Software\Microsoft\Windows\CurrentVersion\App Paths`, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`}),
		"propertyhandlers":    registryProfile("Property Handlers", "Medium", "shell property handler registration surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\PropertySystem\PropertyHandlers`, `Software\Microsoft\Windows\CurrentVersion\PropertySystem\PropertyHandlers`}),
		"explorerext":         registryProfile("Explorer Extensions", "Medium", "Explorer shell extension registration surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions`, `Software\Microsoft\Windows\CurrentVersion\Shell Extensions`}),
		"thumbnailproviders":  registryProfile("Thumbnail Providers", "Medium", "thumbnail provider registration surface", []string{`SOFTWARE\Classes\CLSID`, `Software\Classes\CLSID`}),
		"previewhandlers":     registryProfile("Preview Handlers", "Medium", "preview handler registration surface", []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\PreviewHandlers`, `Software\Microsoft\Windows\CurrentVersion\PreviewHandlers`}),
		"sessionisolation":    mixedProfile("Session Isolation", "Info", "session boundary process surface", []string{`SYSTEM\CurrentControlSet\Control\Terminal Server`}, nil, []string{"winlogon", "csrss", "dwm", "rdpclip"}),
		"windowstations":      registryProfile("Window Stations", "Info", "desktop/window station policy surface", []string{`SYSTEM\CurrentControlSet\Control\Windows`, `SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems`}),
		"clipboard":           mixedProfile("Clipboard IPC", "Info", "clipboard IPC process surface", nil, nil, []string{"rdpclip", "explorer", "applicationframehost"}),
		"dragdrop":            mixedProfile("Drag-and-Drop IPC", "Info", "drag-and-drop broker process surface", nil, nil, []string{"explorer", "runtimebroker", "applicationframehost"}),
		"dde":                 registryProfile("DDE", "Medium", "DDE command registration surface", []string{`Software\Classes`, `SOFTWARE\Classes`}),
		"ole":                 registryProfile("OLE", "Medium", "OLE/COM embedding registration surface", []string{`Software\Classes`, `SOFTWARE\Classes`, `SOFTWARE\Microsoft\Ole`}),
	}
}

func registryProfile(area, severity, reason string, paths []string) surfaceProfile {
	probes := make([]registryProbe, 0, len(paths))
	for _, path := range paths {
		scope := uintptr(registry.HkeyLocalMachine)
		root := "HKLM"
		if strings.HasPrefix(path, "Software\\") || path == "Environment" {
			scope = uintptr(registry.HkeyCurrentUser)
			root = "HKCU"
		}
		if strings.HasPrefix(path, "SOFTWARE\\") || strings.HasPrefix(path, "SYSTEM\\") {
			scope = uintptr(registry.HkeyLocalMachine)
			root = "HKLM"
		}
		probes = append(probes, registryProbe{scope: scope, root: root, path: path})
	}
	return surfaceProfile{area: area, severity: severity, reason: reason, registry: probes}
}

func serviceProfile(area, severity, reason string, services []string) surfaceProfile {
	return surfaceProfile{area: area, severity: severity, reason: reason, services: services}
}

func fileProfile(area, severity, reason string, globs []string) surfaceProfile {
	return surfaceProfile{area: area, severity: severity, reason: reason, globs: globs}
}

func mixedProfile(area, severity, reason string, paths []string, globs []string, processes []string) surfaceProfile {
	profile := registryProfile(area, severity, reason, paths)
	profile.globs = globs
	profile.processes = processes
	return profile
}

func servicesMatching(area string, keywords []string, severity, reason string) []AdvancedFinding {
	services, err := services.EnumerateServices()
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, service := range services {
		if len(keywords) == 1 && keywords[0] == "" || containsKeyword(service.Name, keywords) || containsKeyword(service.DisplayName, keywords) || containsKeyword(service.BinaryPath, keywords) {
			findings = append(findings, AdvancedFinding{Area: area, Target: service.Name, Name: service.StartType, Value: service.BinaryPath, Severity: severity, Reason: reason})
		}
	}
	return findings
}

func processesMatching(area string, keywords []string, severity, reason string) []AdvancedFinding {
	processes, err := winprocess.EnumerateProcesses()
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, process := range processes {
		if containsKeyword(process.Name, keywords) {
			findings = append(findings, AdvancedFinding{Area: area, Target: fmt.Sprintf("%s[%d]", process.Name, process.PID), Name: "process", Severity: severity, Reason: reason})
		}
	}
	return findings
}

func containsKeyword(value string, keywords []string) bool {
	value = strings.ToLower(value)
	for _, keyword := range keywords {
		if keyword == "" || strings.Contains(value, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func expandEnvPath(path string) string {
	replacements := map[string]string{
		"%TEMP%":              os.Getenv("TEMP"),
		"%TMP%":               os.Getenv("TMP"),
		"%WINDIR%":            os.Getenv("WINDIR"),
		"%ProgramData%":       os.Getenv("ProgramData"),
		"%ProgramFiles%":      os.Getenv("ProgramFiles"),
		"%ProgramFiles(x86)%": os.Getenv("ProgramFiles(x86)"),
	}
	for token, value := range replacements {
		if value != "" {
			path = strings.ReplaceAll(path, token, value)
		}
	}
	return path
}
