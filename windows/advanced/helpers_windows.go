//go:build windows

package advanced

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ferrum/windows/registry"
)

func registryNamedValues(area string, scope uintptr, root, path string, names []string, severity, reason string) []AdvancedFinding {
	values, err := registry.Values(scope, path)
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, value := range values {
		if containsName(names, value.Name) {
			findings = append(findings, AdvancedFinding{Area: area, Target: root + `\` + path, Name: displayName(value.Name), Value: value.Value, Severity: severity, Reason: reason})
		}
	}
	return findings
}

func registryAllValues(area string, scope uintptr, root, path, severity, reason string) []AdvancedFinding {
	values, err := registry.Values(scope, path)
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, value := range values {
		findings = append(findings, AdvancedFinding{Area: area, Target: root + `\` + path, Name: displayName(value.Name), Value: value.Value, Severity: severity, Reason: reason})
	}
	return findings
}

func registrySubkeys(area string, scope uintptr, root, path, severity, reason string) []AdvancedFinding {
	keys := subkeys(scope, path)
	findings := make([]AdvancedFinding, 0, len(keys))
	for _, key := range keys {
		findings = append(findings, AdvancedFinding{Area: area, Target: root + `\` + path + `\` + key, Name: key, Severity: severity, Reason: reason})
	}
	return findings
}

func subkeys(scope uintptr, path string) []string {
	key, err := registry.OpenKey(scope, path)
	if err != nil {
		return nil
	}
	defer registry.CloseKey(key)
	keys, err := registry.EnumSubkeys(key)
	if err != nil {
		return nil
	}
	return keys
}

func fileGlobFindings(area, pattern, severity, reason string) []AdvancedFinding {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	findings := []AdvancedFinding{}
	for _, match := range matches {
		findings = append(findings, AdvancedFinding{Area: area, Target: match, Name: filepath.Base(match), Severity: severity, Reason: reason})
	}
	return findings
}

func pathRisk(path string) string {
	trimmed := strings.TrimSpace(path)
	lower := strings.ToLower(trimmed)
	switch {
	case trimmed == "":
		return ""
	case strings.Contains(trimmed, " ") && !strings.HasPrefix(trimmed, `"`) && strings.Contains(lower, ".exe"):
		return "unquoted executable path with spaces"
	case strings.Contains(lower, `\users\`) || strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\downloads\`):
		return "user-writable-looking image path"
	case strings.Contains(lower, `\programdata\`):
		return "commonly writable image path"
	default:
		return ""
	}
}

func exists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func mustCLSID() []registry.CLSIDEntry {
	entries, err := registry.EnumerateHKCUCLSID()
	if err != nil {
		return nil
	}
	return entries
}

func displayName(name string) string {
	if name == "" {
		return "(Default)"
	}
	return name
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

func sortAdvanced(findings []AdvancedFinding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		if findings[i].Area != findings[j].Area {
			return findings[i].Area < findings[j].Area
		}
		return findings[i].Target < findings[j].Target
	})
}

func limitAdvanced(findings []AdvancedFinding) []AdvancedFinding {
	if len(findings) <= advancedLimit {
		return findings
	}
	return findings[:advancedLimit]
}
