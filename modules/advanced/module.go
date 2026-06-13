package advanced

import (
	"fmt"

	"ferrum/core"
	win "ferrum/windows/facade"
)

type definition struct {
	name        string
	description string
}

var definitions = []definition{
	{"comdcom", "Audit COM/DCOM registration and activation surface"},
	{"comelevation", "Audit COM elevation moniker and auto-elevated COM surface"},
	{"dcomactivation", "Audit DCOM activation and machine-wide COM security policy"},
	{"rpc", "Audit RPC endpoint and service registration surface"},
	{"alpc", "Audit ALPC-related object and broker surface"},
	{"lpc", "Audit legacy LPC and object namespace surface"},
	{"tokenimpersonation", "Audit token impersonation privilege and server process surface"},
	{"autoruns", "Audit extended autorun and logon execution locations"},
	{"ifeo", "Audit Image File Execution Options interception settings"},
	{"silentexit", "Audit SilentProcessExit monitor process settings"},
	{"winlogon", "Audit Winlogon shell, userinit, and notification surface"},
	{"lsa", "Audit LSA authentication, notification, and security packages"},
	{"appinit", "Audit AppInit DLL configuration"},
	{"appcert", "Audit AppCert DLL process creation hooks"},
	{"uac", "Audit UAC policy values"},
	{"uacautoelevation", "Audit UAC auto-elevation and consent policy surface"},
	{"installer", "Audit Windows Installer elevation policy"},
	{"msi", "Audit Windows Installer and repair abuse surface"},
	{"installerrepair", "Audit MSI repair and advertised shortcut abuse surface"},
	{"powershell", "Audit PowerShell policy and profile surface"},
	{"applocker", "Audit AppLocker and SRP policy presence"},
	{"wdac", "Audit Windows Defender Application Control policy presence"},
	{"wdacpolicy", "Audit WDAC and AppLocker policy interface surface"},
	{"defender", "Audit Microsoft Defender policy and exclusions"},
	{"firewall", "Audit Windows Firewall profile posture"},
	{"rdp", "Audit Remote Desktop exposure policy"},
	{"brokers", "Audit privileged broker process and COM broker surface"},
	{"appcontainerbrokers", "Audit AppContainer broker and capability surface"},
	{"wmi", "Audit WMI repository and AutoRecover MOF surface"},
	{"hosts", "Inspect hosts file overrides"},
	{"shares", "Audit configured LanmanServer shares"},
	{"shell", "Audit Explorer shell extension and delay-load surface"},
	{"browser", "Audit browser helper and native messaging extension surface"},
	{"protocols", "Audit custom URL protocol handlers"},
	{"urlmonikers", "Audit URL moniker and protocol activation surface"},
	{"comlocal", "Audit per-user COM local/inproc server registrations"},
	{"comhijack", "Audit COM registration hijacking surface"},
	{"custommarshal", "Audit COM custom marshaling registration surface"},
	{"knowndlls", "Inventory KnownDLL protected names"},
	{"dllhijacking", "Audit DLL hijacking and search-order abuse surface"},
	{"sxs", "Audit side-by-side assembly and activation context surface"},
	{"activationctx", "Audit manifest and activation context abuse surface"},
	{"ntobjmgr", "Audit NT Object Manager namespace surface"},
	{"objdirs", "Audit object directory namespace surface"},
	{"symlinks", "Audit symbolic link surface"},
	{"hardlinks", "Audit hard link research surface"},
	{"junctions", "Audit junction and directory link surface"},
	{"mountpoints", "Audit mount point surface"},
	{"reparsepoints", "Audit reparse point surface"},
	{"oplocks", "Audit opportunistic lock race research surface"},
	{"regsymlinks", "Audit registry symbolic link surface"},
	{"svcpaths", "Audit service image path risk at scale"},
	{"scm", "Audit Service Control Manager and service configuration surface"},
	{"driverpaths", "Audit driver image path risk at scale"},
	{"minifilters", "Audit file system minifilter driver surface"},
	{"ioctls", "Audit kernel driver IOCTL and device exposure surface"},
	{"deviceobjects", "Audit device object namespace exposure"},
	{"etw", "Audit Event Tracing for Windows provider surface"},
	{"win32k", "Audit Win32k and GUI subsystem boundary surface"},
	{"csrss", "Audit CSRSS and console subsystem boundary surface"},
	{"lsassinterfaces", "Audit LSASS interfaces and authentication package surface"},
	{"accesstokens", "Audit access token privilege and integrity surface"},
	{"handles", "Audit handle duplication and leak research surface"},
	{"jobobjects", "Audit job object namespace and process containment surface"},
	{"sectionobjects", "Audit section object and shared memory surface"},
	{"sharedmemory", "Audit shared memory object namespace surface"},
	{"mmap", "Audit memory-mapped file surface"},
	{"wfp", "Audit Windows Filtering Platform provider surface"},
	{"hyperv", "Audit Hyper-V component and service surface"},
	{"wsl", "Audit Windows Subsystem for Linux component surface"},
	{"certificates", "Inventory machine and user certificate store density"},
	{"networkproviders", "Audit credential and network provider load order"},
	{"print", "Audit print monitor, provider, and processor surface"},
	{"efsrpc", "Audit EFSRPC service and RPC exposure surface"},
	{"taskrpc", "Audit Task Scheduler RPC surface"},
	{"bits", "Audit Background Intelligent Transfer Service surface"},
	{"endpointmapper", "Audit DCOM/RPC Endpoint Mapper surface"},
	{"winrm", "Audit Windows Remote Management surface"},
	{"smbipc", "Audit SMB local IPC and LanmanServer surface"},
	{"credproviders", "Audit credential provider and filter surface"},
	{"authpackages", "Audit authentication package registration surface"},
	{"lsaplugins", "Audit LSA plugin registration surface"},
	{"cloudap", "Audit CloudAP and cloud authentication package surface"},
	{"ppl", "Audit Protected Process Light boundary indicators"},
	{"userprofilesvc", "Audit User Profile Service and profile path surface"},
	{"updates", "Audit update mechanism service and policy surface"},
	{"recovery", "Audit repair and recovery mechanism surface"},
	{"tempfiles", "Audit temporary file handling risk surface"},
	{"toctou", "Audit TOCTOU and race-prone filesystem surface"},
	{"pathcanon", "Audit path canonicalization risk surface"},
	{"confuseddeputy", "Audit confused deputy research surface"},
	{"acl", "Audit file and registry ACL misconfiguration surface"},
	{"envinjection", "Audit environment variable injection surface"},
	{"searchpoison", "Audit search path poisoning surface"},
	{"propertyhandlers", "Audit shell property handler surface"},
	{"explorerext", "Audit Explorer extension surface"},
	{"thumbnailproviders", "Audit thumbnail provider surface"},
	{"previewhandlers", "Audit preview handler surface"},
	{"winsock", "Audit Winsock catalog and namespace provider surface"},
	{"accessibility", "Audit accessibility binary interception surface"},
	{"sessionisolation", "Audit session isolation boundary surface"},
	{"windowstations", "Audit desktop and window station object surface"},
	{"clipboard", "Audit clipboard IPC surface"},
	{"dragdrop", "Audit drag-and-drop IPC surface"},
	{"dde", "Audit Dynamic Data Exchange surface"},
	{"ole", "Audit OLE automation and embedding surface"},
}

func init() {
	for _, def := range definitions {
		core.Register(module{definition: def})
	}
}

type module struct {
	definition
}

func (m module) Name() string { return m.name }

func (m module) Description() string { return m.description }

func (m module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Running " + m.name + " audit...")
	findings, err := win.EnumerateAdvancedFindings(m.name)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		ctx.Logger.Info("No findings returned for " + m.name + ".")
		return nil
	}
	for _, finding := range findings {
		ctx.Logger.Success(fmt.Sprintf("%s %s > %s", finding.Severity, finding.Target, finding.Reason))
		if finding.Name != "" || finding.Value != "" {
			ctx.Logger.Verbose(fmt.Sprintf("%s : %s = %s", finding.Area, finding.Name, finding.Value))
		}
	}
	return nil
}
