//go:build windows

package audit

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ferrum/windows/registry"
	wintypes "ferrum/windows/types"
)

type RegistryAuditFinding = registry.RegistryAuditFinding
type PolicyFinding = wintypes.PolicyFinding
type DLLSearchPathFinding = wintypes.DLLSearchPathFinding

func EnumerateRegistryAuditFindings() ([]RegistryAuditFinding, error) {
	findings := []RegistryAuditFinding{}
	checkValueSet := []struct {
		scope     uintptr
		scopeName string
		path      string
		names     []string
		severity  string
		reason    string
	}{
		{registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, []string{"AppInit_DLLs", "LoadAppInit_DLLs"}, "High", "AppInit DLL injection surface"},
		{registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager`, []string{"AppCertDLLs"}, "High", "process creation DLL injection surface"},
		{registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, []string{"Shell", "Userinit", "Notify"}, "High", "Winlogon execution surface"},
		{registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Lsa`, []string{"Authentication Packages", "Notification Packages", "Security Packages"}, "High", "LSA package load surface"},
		{registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`, []string{"Debugger", "Auto"}, "Medium", "post-crash debugger execution surface"},
		{registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, []string{"EnableLUA", "ConsentPromptBehaviorAdmin", "LocalAccountTokenFilterPolicy"}, "Medium", "UAC and remote token policy"},
		{registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager`, []string{"SafeDllSearchMode", "CWDIllegalInDllSearch"}, "Medium", "DLL search-order policy"},
		{registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Policies\Microsoft\Windows\PowerShell`, []string{"EnableScripts", "ExecutionPolicy"}, "Medium", "PowerShell execution policy"},
		{registry.HkeyCurrentUser, "HKCU", `SOFTWARE\Policies\Microsoft\Windows\PowerShell`, []string{"EnableScripts", "ExecutionPolicy"}, "Medium", "per-user PowerShell policy"},
	}
	for _, check := range checkValueSet {
		values, err := registry.Values(check.scope, check.path)
		if err != nil {
			continue
		}
		for _, value := range values {
			if !containsName(check.names, value.Name) {
				continue
			}
			findings = append(findings, RegistryAuditFinding{
				Scope:    check.scopeName,
				Path:     check.path,
				Name:     value.Name,
				Value:    value.Value,
				Severity: check.severity,
				Reason:   check.reason,
			})
		}
	}

	findings = append(findings, enumerateIFEO(registry.HkeyLocalMachine, "HKLM")...)
	findings = append(findings, enumerateIFEO(registry.HkeyCurrentUser, "HKCU")...)
	findings = append(findings, enumerateSilentProcessExit()...)
	findings = append(findings, enumerateCOMTreatAs()...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Scope+findings[i].Path+findings[i].Name < findings[j].Scope+findings[j].Path+findings[j].Name
	})
	return findings, nil
}

func EnumeratePolicyFindings() ([]PolicyFinding, error) {
	findings := []PolicyFinding{}
	if enabled(registry.HkeyCurrentUser, `Software\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated") &&
		enabled(registry.HkeyLocalMachine, `Software\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated") {
		findings = append(findings, PolicyFinding{Name: "AlwaysInstallElevated", Value: "HKCU=1 HKLM=1", Severity: "High", Reason: "MSI packages can install elevated for standard users"})
	}
	if value := registryValue(registry.HkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"); value == "00000000" || value == "0" {
		findings = append(findings, PolicyFinding{Name: "EnableLUA", Value: value, Severity: "High", Reason: "UAC disabled"})
	}
	if value := registryValue(registry.HkeyLocalMachine, `SYSTEM\CurrentControlSet\Control\Session Manager`, "SafeDllSearchMode"); value == "00000000" || value == "0" {
		findings = append(findings, PolicyFinding{Name: "SafeDllSearchMode", Value: value, Severity: "Medium", Reason: "legacy DLL search behavior"})
	}
	if hasSubkeys(registry.HkeyLocalMachine, `SOFTWARE\Policies\Microsoft\Windows\SrpV2`) {
		findings = append(findings, PolicyFinding{Name: "AppLocker", Value: "Configured", Severity: "Info", Reason: "application control policy present"})
	} else {
		findings = append(findings, PolicyFinding{Name: "AppLocker", Value: "Not detected", Severity: "Low", Reason: "no AppLocker policy keys found"})
	}
	if hasSubkeys(registry.HkeyLocalMachine, `SYSTEM\CurrentControlSet\Control\CI\Policy`) {
		findings = append(findings, PolicyFinding{Name: "WDAC", Value: "Policy keys present", Severity: "Info", Reason: "code integrity policy surface present"})
	} else {
		findings = append(findings, PolicyFinding{Name: "WDAC", Value: "Not detected", Severity: "Low", Reason: "no WDAC policy keys found"})
	}
	return findings, nil
}

func EnumerateDLLSearchPathFindings() ([]DLLSearchPathFinding, error) {
	findings := []DLLSearchPathFinding{}
	pathValue := os.Getenv("PATH")
	seen := map[string]bool{}
	for _, path := range filepath.SplitList(pathValue) {
		path = strings.TrimSpace(path)
		if path == "" || seen[strings.ToLower(path)] {
			continue
		}
		seen[strings.ToLower(path)] = true
		reason, severity := classifySearchPath(path)
		if reason == "" {
			continue
		}
		findings = append(findings, DLLSearchPathFinding{Path: path, Source: "PATH", Severity: severity, Reason: reason})
	}
	if cwd, err := os.Getwd(); err == nil {
		reason, severity := classifySearchPath(cwd)
		if reason != "" {
			findings = append(findings, DLLSearchPathFinding{Path: cwd, Source: "CurrentDirectory", Severity: severity, Reason: reason})
		}
	}
	for _, known := range knownDLLs() {
		findings = append(findings, DLLSearchPathFinding{Path: known, Source: "KnownDLLs", Severity: "Info", Reason: "KnownDLL protected load name"})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Path < findings[j].Path
	})
	return findings, nil
}

func enumerateIFEO(scope uintptr, scopeName string) []RegistryAuditFinding {
	base := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	root, err := registry.OpenKey(scope, base)
	if err != nil {
		return nil
	}
	defer registry.CloseKey(root)
	keys, err := registry.EnumSubkeys(root)
	if err != nil {
		return nil
	}
	findings := []RegistryAuditFinding{}
	for _, key := range keys {
		values, err := registry.Values(scope, base+`\`+key)
		if err != nil {
			continue
		}
		for _, value := range values {
			if containsName([]string{"Debugger", "VerifierDlls", "GlobalFlag"}, value.Name) {
				findings = append(findings, RegistryAuditFinding{Scope: scopeName, Path: base + `\` + key, Name: value.Name, Value: value.Value, Severity: "High", Reason: "IFEO process interception or verifier surface"})
			}
		}
	}
	return findings
}

func enumerateSilentProcessExit() []RegistryAuditFinding {
	base := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
	root, err := registry.OpenKey(registry.HkeyLocalMachine, base)
	if err != nil {
		return nil
	}
	defer registry.CloseKey(root)
	keys, err := registry.EnumSubkeys(root)
	if err != nil {
		return nil
	}
	findings := []RegistryAuditFinding{}
	for _, key := range keys {
		values, err := registry.Values(registry.HkeyLocalMachine, base+`\`+key)
		if err != nil {
			continue
		}
		for _, value := range values {
			if containsName([]string{"MonitorProcess", "ReportingMode"}, value.Name) {
				findings = append(findings, RegistryAuditFinding{Scope: "HKLM", Path: base + `\` + key, Name: value.Name, Value: value.Value, Severity: "High", Reason: "SilentProcessExit monitor execution surface"})
			}
		}
	}
	return findings
}

func enumerateCOMTreatAs() []RegistryAuditFinding {
	base := `Software\Classes\CLSID`
	root, err := registry.OpenKey(registry.HkeyCurrentUser, base)
	if err != nil {
		return nil
	}
	defer registry.CloseKey(root)
	keys, err := registry.EnumSubkeys(root)
	if err != nil {
		return nil
	}
	findings := []RegistryAuditFinding{}
	for _, key := range keys {
		treatAs, err := registry.OpenKey(root, key+`\TreatAs`)
		if err != nil {
			continue
		}
		value, _ := registry.QueryDefaultValue(treatAs)
		registry.CloseKey(treatAs)
		findings = append(findings, RegistryAuditFinding{Scope: "HKCU", Path: base + `\` + key + `\TreatAs`, Name: "(Default)", Value: value, Severity: "Medium", Reason: "per-user COM TreatAs redirection"})
	}
	return findings
}

func classifySearchPath(path string) (string, string) {
	lower := strings.ToLower(path)
	switch {
	case path == "." || !filepath.IsAbs(path):
		return "relative DLL search path element", "High"
	case strings.Contains(lower, `\users\`) || strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\downloads\`):
		return "user-writable-looking DLL search path element", "High"
	case strings.Contains(lower, `\programdata\`):
		return "commonly writable DLL search path element", "Medium"
	}
	if _, err := os.Stat(path); err != nil {
		return "missing DLL search path element", "Low"
	}
	return "", ""
}

func knownDLLs() []string {
	values, err := registry.Values(registry.HkeyLocalMachine, `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
	if err != nil {
		return nil
	}
	names := []string{}
	for _, value := range values {
		if value.Name == "" || strings.HasPrefix(value.Name, "DllDirectory") {
			continue
		}
		names = append(names, value.Value)
	}
	return names
}

func registryValue(scope uintptr, path, name string) string {
	values, err := registry.Values(scope, path)
	if err != nil {
		return ""
	}
	for _, value := range values {
		if strings.EqualFold(value.Name, name) {
			return value.Value
		}
	}
	return ""
}

func enabled(scope uintptr, path, name string) bool {
	value := registryValue(scope, path, name)
	return value == "1" || value == "00000001"
}

func hasSubkeys(scope uintptr, path string) bool {
	key, err := registry.OpenKey(scope, path)
	if err != nil {
		return false
	}
	defer registry.CloseKey(key)
	keys, err := registry.EnumSubkeys(key)
	return err == nil && len(keys) > 0
}

func containsName(names []string, name string) bool {
	for _, item := range names {
		if strings.EqualFold(item, name) {
			return true
		}
	}
	return false
}

func severityRank(severity string) int {
	switch severity {
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Info":
		return 1
	default:
		return 0
	}
}
