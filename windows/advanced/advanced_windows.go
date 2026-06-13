//go:build windows

package advanced

import (
	"os"
	"path/filepath"

	"ferrum/windows/registry"
	wintypes "ferrum/windows/types"
)

type AdvancedFinding = wintypes.AdvancedFinding

func EnumerateAdvancedFindings(check string) ([]AdvancedFinding, error) {
	var findings []AdvancedFinding
	switch check {
	case "autoruns":
		findings = autorunFindings()
	case "ifeo":
		findings = ifeoFindings()
	case "silentexit":
		findings = silentExitFindings()
	case "winlogon":
		findings = registryNamedValues("Winlogon", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, []string{"Shell", "Userinit", "Notify", "GinaDLL"}, "High", "logon execution surface")
	case "lsa":
		findings = registryNamedValues("LSA", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Lsa`, []string{"Authentication Packages", "Notification Packages", "Security Packages", "RunAsPPL", "LsaCfgFlags"}, "High", "LSA package or protection setting")
	case "appinit":
		findings = registryNamedValues("AppInit", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, []string{"LoadAppInit_DLLs", "AppInit_DLLs", "RequireSignedAppInit_DLLs"}, "High", "AppInit DLL load surface")
	case "appcert":
		findings = registryAllValues("AppCert", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs`, "High", "AppCert DLL process creation hook")
	case "uac":
		findings = registryNamedValues("UAC", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, []string{"EnableLUA", "ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorUser", "LocalAccountTokenFilterPolicy", "FilterAdministratorToken"}, "Medium", "UAC policy value")
	case "installer":
		findings = append(findings, registryNamedValues("Installer", registry.HkeyCurrentUser, "HKCU", `Software\Policies\Microsoft\Windows\Installer`, []string{"AlwaysInstallElevated", "DisableMSI"}, "High", "per-user installer elevation policy")...)
		findings = append(findings, registryNamedValues("Installer", registry.HkeyLocalMachine, "HKLM", `Software\Policies\Microsoft\Windows\Installer`, []string{"AlwaysInstallElevated", "DisableMSI"}, "High", "machine installer elevation policy")...)
	case "powershell":
		findings = powershellFindings()
	case "applocker":
		findings = registrySubkeys("AppLocker", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Policies\Microsoft\Windows\SrpV2`, "Info", "AppLocker rule collection")
		findings = append(findings, registrySubkeys("SRP", registry.HkeyLocalMachine, "HKLM", `SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers`, "Info", "Software Restriction Policy surface")...)
	case "wdac":
		findings = registrySubkeys("WDAC", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\CI\Policy`, "Info", "code integrity policy key")
		findings = append(findings, fileGlobFindings("WDAC", filepath.Join(os.Getenv("WINDIR"), `System32\CodeIntegrity`, "*.cip"), "Info", "WDAC policy file")...)
	case "defender":
		findings = defenderFindings()
	case "firewall":
		findings = firewallFindings()
	case "rdp":
		findings = rdpFindings()
	case "wmi":
		findings = wmiFindings()
	case "hosts":
		findings = hostsFindings()
	case "shares":
		findings = registryAllValues("Shares", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`, "Medium", "configured SMB share")
	case "shell":
		findings = shellFindings()
	case "browser":
		findings = browserFindings()
	case "protocols":
		findings = protocolFindings()
	case "comlocal":
		findings = comLocalFindings()
	case "knowndlls":
		findings = registryAllValues("KnownDLLs", registry.HkeyLocalMachine, "HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, "Info", "KnownDLL protected load name")
	case "svcpaths":
		findings = servicePathFindings()
	case "driverpaths":
		findings = driverPathFindings()
	case "certificates":
		findings = certificateFindings()
	case "networkproviders":
		findings = networkProviderFindings()
	case "print":
		findings = printFindings()
	case "winsock":
		findings = winsockFindings()
	case "accessibility":
		findings = accessibilityFindings()
	default:
		findings = genericSurfaceFindings(check)
	}
	sortAdvanced(findings)
	return findings, nil
}
