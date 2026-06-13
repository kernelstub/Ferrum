//go:build windows

package advanced

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ferrum/windows/registry"
	"ferrum/windows/services"
)

func autorunFindings() []AdvancedFinding {
	checks := []struct {
		scope uintptr
		root  string
		path  string
	}{
		{registry.HkeyCurrentUser, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.HkeyCurrentUser, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.HkeyCurrentUser, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunServices`},
		{registry.HkeyLocalMachine, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.HkeyLocalMachine, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.HkeyLocalMachine, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunServices`},
		{registry.HkeyLocalMachine, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	}
	findings := []AdvancedFinding{}
	for _, check := range checks {
		findings = append(findings, registryAllValues("Autoruns", check.scope, check.root, check.path, "Medium", "autorun execution entry")...)
	}
	return findings
}

func ifeoFindings() []AdvancedFinding {
	findings := []AdvancedFinding{}
	for _, root := range []struct {
		scope uintptr
		name  string
	}{{registry.HkeyLocalMachine, "HKLM"}, {registry.HkeyCurrentUser, "HKCU"}} {
		base := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
		for _, key := range subkeys(root.scope, base) {
			findings = append(findings, registryNamedValues("IFEO", root.scope, root.name, base+`\`+key, []string{"Debugger", "VerifierDlls", "GlobalFlag", "MitigationOptions"}, "High", "process interception or verifier setting")...)
		}
	}
	return findings
}

func silentExitFindings() []AdvancedFinding {
	findings := []AdvancedFinding{}
	base := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
	for _, key := range subkeys(registry.HkeyLocalMachine, base) {
		findings = append(findings, registryNamedValues("SilentProcessExit", registry.HkeyLocalMachine, "HKLM", base+`\`+key, []string{"MonitorProcess", "ReportingMode", "LocalDumpFolder"}, "High", "process-exit monitor or dump surface")...)
	}
	return findings
}

func powershellFindings() []AdvancedFinding {
	findings := []AdvancedFinding{}
	for _, root := range []struct {
		scope uintptr
		name  string
	}{{registry.HkeyLocalMachine, "HKLM"}, {registry.HkeyCurrentUser, "HKCU"}} {
		findings = append(findings, registryAllValues("PowerShell", root.scope, root.name, `SOFTWARE\Policies\Microsoft\Windows\PowerShell`, "Medium", "PowerShell policy value")...)
		findings = append(findings, registryAllValues("PowerShell", root.scope, root.name, `SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`, "Medium", "PowerShell shell policy value")...)
	}
	profiles := []string{
		filepath.Join(os.Getenv("USERPROFILE"), `Documents\WindowsPowerShell\profile.ps1`),
		filepath.Join(os.Getenv("USERPROFILE"), `Documents\PowerShell\profile.ps1`),
		filepath.Join(os.Getenv("WINDIR"), `System32\WindowsPowerShell\v1.0\profile.ps1`),
	}
	for _, profile := range profiles {
		if exists(profile) {
			findings = append(findings, AdvancedFinding{Area: "PowerShell", Target: profile, Name: "profile", Severity: "Medium", Reason: "PowerShell profile script present"})
		}
	}
	return findings
}

func defenderFindings() []AdvancedFinding {
	findings := registryAllValues("Defender", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Policies\Microsoft\Windows Defender`, "High", "Defender policy value")
	findings = append(findings, registryAllValues("DefenderExclusions", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, "Medium", "Defender path exclusion")...)
	findings = append(findings, registryAllValues("DefenderExclusions", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`, "Medium", "Defender process exclusion")...)
	findings = append(findings, registryAllValues("DefenderFeatures", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows Defender\Features`, "Info", "Defender feature value")...)
	return findings
}

func firewallFindings() []AdvancedFinding {
	base := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
	profiles := []string{"DomainProfile", "PublicProfile", "StandardProfile"}
	findings := []AdvancedFinding{}
	for _, profile := range profiles {
		findings = append(findings, registryNamedValues("Firewall", registry.HkeyLocalMachine, "HKLM", base+`\`+profile, []string{"EnableFirewall", "DefaultInboundAction", "DefaultOutboundAction", "DisableNotifications"}, "Medium", profile+" firewall policy")...)
	}
	return findings
}

func rdpFindings() []AdvancedFinding {
	findings := registryNamedValues("RDP", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Terminal Server`, []string{"fDenyTSConnections", "fSingleSessionPerUser"}, "Medium", "Remote Desktop terminal server policy")
	findings = append(findings, registryNamedValues("RDP", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, []string{"UserAuthentication", "SecurityLayer", "PortNumber"}, "Medium", "RDP listener policy")...)
	return findings
}

func wmiFindings() []AdvancedFinding {
	findings := fileGlobFindings("WMI", filepath.Join(os.Getenv("WINDIR"), `System32\wbem\AutoRecover`, "*.mof"), "Medium", "WMI AutoRecover MOF")
	findings = append(findings, registryAllValues("WMI", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\WBEM\CIMOM`, "Info", "WMI CIMOM configuration")...)
	return findings
}

func hostsFindings() []AdvancedFinding {
	path := filepath.Join(os.Getenv("WINDIR"), `System32\drivers\etc\hosts`)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		findings = append(findings, AdvancedFinding{Area: "Hosts", Target: path, Name: "entry", Value: line, Severity: "Medium", Reason: "hosts file override"})
	}
	return findings
}

func shellFindings() []AdvancedFinding {
	findings := registryAllValues("Shell", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, "Medium", "shell service object delay-load entry")
	findings = append(findings, registryAllValues("Shell", registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, "Medium", "per-user shell service object delay-load entry")...)
	findings = append(findings, registrySubkeys("ShellExtensions", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`, "Info", "approved shell extension")...)
	findings = append(findings, registryAllValues("ExplorerPolicies", registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "Medium", "Explorer policy value")...)
	return findings
}

func browserFindings() []AdvancedFinding {
	findings := registrySubkeys("Browser", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, "Medium", "Browser Helper Object")
	findings = append(findings, registrySubkeys("Browser", registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, "Medium", "per-user Browser Helper Object")...)
	findings = append(findings, registrySubkeys("Browser", registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Google\Chrome\NativeMessagingHosts`, "Medium", "Chrome native messaging host")...)
	findings = append(findings, registrySubkeys("Browser", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Google\Chrome\NativeMessagingHosts`, "Medium", "machine Chrome native messaging host")...)
	findings = append(findings, registrySubkeys("Browser", registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Microsoft\Edge\NativeMessagingHosts`, "Medium", "Edge native messaging host")...)
	return findings
}

func protocolFindings() []AdvancedFinding {
	findings := []AdvancedFinding{}
	for _, root := range []struct {
		scope uintptr
		name  string
	}{{registry.HkeyCurrentUser, "HKCU"}, {registry.HkeyLocalMachine, "HKLM"}} {
		base := `Software\Classes`
		for _, key := range subkeys(root.scope, base) {
			values, err := registry.Values(root.scope, base+`\`+key)
			if err != nil {
				continue
			}
			for _, value := range values {
				if strings.EqualFold(value.Name, "URL Protocol") {
					findings = append(findings, AdvancedFinding{Area: "Protocols", Target: root.name + `\` + base + `\` + key, Name: value.Name, Value: value.Value, Severity: "Medium", Reason: "custom URL protocol handler"})
				}
			}
		}
	}
	return findings
}

func comLocalFindings() []AdvancedFinding {
	findings := []AdvancedFinding{}
	for _, entry := range mustCLSID() {
		if entry.Kind == "InprocServer32" || entry.Kind == "LocalServer32" {
			findings = append(findings, AdvancedFinding{Area: "COM", Target: `HKCU\Software\Classes\CLSID\` + entry.CLSID, Name: entry.Kind, Value: entry.Value, Severity: "Medium", Reason: "per-user COM server registration"})
		}
	}
	return findings
}

func servicePathFindings() []AdvancedFinding {
	services, err := services.EnumerateServices()
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, service := range services {
		if reason := pathRisk(service.BinaryPath); reason != "" {
			findings = append(findings, AdvancedFinding{Area: "Services", Target: service.Name, Name: service.StartType, Value: service.BinaryPath, Severity: "High", Reason: reason})
		}
	}
	return findings
}

func driverPathFindings() []AdvancedFinding {
	drivers, err := services.EnumerateDrivers()
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, driver := range drivers {
		if reason := pathRisk(driver.BinaryPath); reason != "" {
			findings = append(findings, AdvancedFinding{Area: "Drivers", Target: driver.Name, Name: driver.StartType, Value: driver.BinaryPath, Severity: "High", Reason: reason})
		}
	}
	return findings
}

func certificateFindings() []AdvancedFinding {
	checks := []struct {
		scope uintptr
		root  string
		path  string
	}{
		{registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`},
		{registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates`},
		{registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`},
		{registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Microsoft\SystemCertificates\My\Certificates`},
	}
	findings := []AdvancedFinding{}
	for _, check := range checks {
		keys := subkeys(check.scope, check.path)
		findings = append(findings, AdvancedFinding{Area: "Certificates", Target: check.root + `\` + check.path, Name: "count", Value: fmt.Sprintf("%d", len(keys)), Severity: "Info", Reason: "certificate store inventory"})
	}
	return findings
}

func networkProviderFindings() []AdvancedFinding {
	findings := registryAllValues("NetworkProviders", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`, "Medium", "network provider order")
	findings = append(findings, registrySubkeys("CredentialProviders", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`, "Medium", "credential provider")...)
	findings = append(findings, registrySubkeys("CredentialProviderFilters", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters`, "Medium", "credential provider filter")...)
	return findings
}

func printFindings() []AdvancedFinding {
	findings := registrySubkeys("Print", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Print\Monitors`, "Medium", "print monitor load surface")
	findings = append(findings, registrySubkeys("Print", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Print\Providers`, "Medium", "print provider load surface")...)
	findings = append(findings, registrySubkeys("Print", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors`, "Medium", "print processor load surface")...)
	return findings
}

func winsockFindings() []AdvancedFinding {
	findings := registryAllValues("Winsock", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9`, "Info", "Winsock protocol catalog")
	findings = append(findings, registryAllValues("Winsock", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5`, "Info", "Winsock namespace catalog")...)
	return findings
}

func accessibilityFindings() []AdvancedFinding {
	binaries := []string{"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"}
	base := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	findings := []AdvancedFinding{}
	for _, binary := range binaries {
		findings = append(findings, registryNamedValues("Accessibility", registry.HkeyLocalMachine, "HKLM", base+`\`+binary, []string{"Debugger", "VerifierDlls", "GlobalFlag"}, "High", "accessibility binary interception")...)
	}
	return findings
}
