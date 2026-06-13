package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ferrum/core"
	_ "ferrum/modules/advanced"
	_ "ferrum/modules/clsid"
	_ "ferrum/modules/dllsearch"
	_ "ferrum/modules/drivers"
	_ "ferrum/modules/env"
	_ "ferrum/modules/mitigations"
	_ "ferrum/modules/pipes"
	_ "ferrum/modules/policy"
	_ "ferrum/modules/registry"
	_ "ferrum/modules/scheduled"
	_ "ferrum/modules/services"
	_ "ferrum/modules/startup"
	_ "ferrum/modules/tokens"
	"ferrum/output"
)

const build = "Development"

// Module packages register these command flags through core.Register during init.
// Flags are parsed case-insensitively and displayed in uppercase by --HELP.
var registeredModuleFlags = []string{
	"--ACCESSIBILITY",
	"--ACCESSTOKENS",
	"--ACL",
	"--ACTIVATIONCTX",
	"--ALPC",
	"--APPCERT",
	"--APPINIT",
	"--APPLOCKER",
	"--APPCONTAINERBROKERS",
	"--AUTORUNS",
	"--AUTHPACKAGES",
	"--BITS",
	"--BROKERS",
	"--BROWSER",
	"--CERTIFICATES",
	"--CLSID",
	"--CLIPBOARD",
	"--CLOUDAP",
	"--COMDCOM",
	"--COMELEVATION",
	"--COMHIJACK",
	"--COMLOCAL",
	"--CONFUSEDDEPUTY",
	"--CREDPROVIDERS",
	"--CSRSS",
	"--CUSTOMMARSHAL",
	"--DCOMACTIVATION",
	"--DDE",
	"--DEFENDER",
	"--DEVICEOBJECTS",
	"--DLLHIJACKING",
	"--DLLSEARCH",
	"--DRAGDROP",
	"--DRIVERPATHS",
	"--DRIVERS",
	"--EFSRPC",
	"--ENDPOINTMAPPER",
	"--ENV",
	"--ENVINJECTION",
	"--ETW",
	"--EXPLOREREXT",
	"--FIREWALL",
	"--HANDLES",
	"--HARDLINKS",
	"--HOSTS",
	"--HYPERV",
	"--IFEO",
	"--INSTALLER",
	"--INSTALLERREPAIR",
	"--IOCTLS",
	"--JOBOBJECTS",
	"--JUNCTIONS",
	"--KNOWNDLLS",
	"--LPC",
	"--LSA",
	"--LSAPLUGINS",
	"--LSASSINTERFACES",
	"--MITIGATIONS",
	"--MINIFILTERS",
	"--MMAP",
	"--MOUNTPOINTS",
	"--MSI",
	"--NETWORKPROVIDERS",
	"--NTOBJMGR",
	"--OBJDIRS",
	"--OLE",
	"--OPLOCKS",
	"--PATHCANON",
	"--PIPES",
	"--POLICY",
	"--POWERSHELL",
	"--PPL",
	"--PREVIEWHANDLERS",
	"--PRINT",
	"--PROPERTYHANDLERS",
	"--PROTOCOLS",
	"--RDP",
	"--RECOVERY",
	"--REGSYMLINKS",
	"--REGISTRY",
	"--REPARSEPOINTS",
	"--RPC",
	"--SCHEDULED",
	"--SCM",
	"--SEARCHPOISON",
	"--SECTIONOBJECTS",
	"--SERVICES",
	"--SESSIONISOLATION",
	"--SHARES",
	"--SHAREDMEMORY",
	"--SHELL",
	"--SILENTEXIT",
	"--SMBIPC",
	"--STARTUP",
	"--SVCPATHS",
	"--SXS",
	"--SYMLINKS",
	"--TASKRPC",
	"--TEMPFILES",
	"--THUMBNAILPROVIDERS",
	"--TOKENS",
	"--TOKENIMPERSONATION",
	"--TOCTOU",
	"--UAC",
	"--UACAUTOELEVATION",
	"--UPDATES",
	"--URLMONIKERS",
	"--USERPROFILESVC",
	"--WDAC",
	"--WDACPOLICY",
	"--WINLOGON",
	"--WIN32K",
	"--WINRM",
	"--WINSOCK",
	"--WFP",
	"--WINDOWSTATIONS",
	"--WMI",
	"--WSL",
}

func main() {
	fmt.Print(core.Banner(build))

	modules := core.Modules()
	flags, err := parseArgs(os.Args[1:], modules)
	logger := output.NewConsoleLogger(os.Stdout, flags.Verbose, flags.Quiet)

	if err != nil {
		logger.Error(err.Error())
		printHelp(modules)
		os.Exit(2)
	}
	if flags.Help || len(flags.Selected) == 0 {
		printHelp(modules)
		return
	}

	if flags.RunAll {
		if err := runAllToDirectory(flags, modules); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		return
	}

	closeOutput, logger, err := outputLogger(flags)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	defer closeOutput()
	ctx := core.NewContext(logger, build)

	for _, module := range flags.Selected {
		if err := module.Run(ctx); err != nil {
			logger.Error(fmt.Sprintf("%s: %v", module.Name(), err))
		}
	}
}

type cliFlags struct {
	Help       bool
	Quiet      bool
	Verbose    bool
	RunAll     bool
	OutputPath string
	Selected   []core.Module
}

func parseArgs(args []string, modules []core.Module) (cliFlags, error) {
	var flags cliFlags
	byFlag := make(map[string]core.Module, len(modules))
	for _, module := range modules {
		byFlag["--"+module.Name()] = module
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		normalized := strings.ToLower(arg)
		switch {
		case normalized == "--all":
			flags.RunAll = true
			flags.Selected = append(flags.Selected, modules...)
		case normalized == "--output":
			if i+1 >= len(args) {
				return flags, fmt.Errorf("--OUTPUT requires a file path")
			}
			i++
			flags.OutputPath = args[i]
		case strings.HasPrefix(normalized, "--output="):
			flags.OutputPath = arg[len("--output="):]
			if flags.OutputPath == "" {
				return flags, fmt.Errorf("--OUTPUT requires a file path")
			}
		case normalized == "--help" || normalized == "-h" || normalized == "/?":
			flags.Help = true
		case normalized == "--verbose" || normalized == "-v":
			flags.Verbose = true
		case normalized == "--quiet" || normalized == "-q":
			flags.Quiet = true
		default:
			module, ok := byFlag[normalized]
			if !ok {
				return flags, fmt.Errorf("unknown option: %s", arg)
			}
			flags.Selected = append(flags.Selected, module)
		}
	}

	if flags.Quiet {
		flags.Verbose = false
	}
	return flags, nil
}

func outputLogger(flags cliFlags) (func(), *output.ConsoleLogger, error) {
	if flags.OutputPath == "" {
		return func() {}, output.NewConsoleLogger(os.Stdout, flags.Verbose, flags.Quiet), nil
	}
	if err := ensureParent(flags.OutputPath); err != nil {
		return nil, nil, err
	}
	file, err := os.Create(flags.OutputPath)
	if err != nil {
		return nil, nil, err
	}
	return func() { _ = file.Close() }, output.NewDualLogger(os.Stdout, file, flags.Verbose, flags.Quiet), nil
}

func runAllToDirectory(flags cliFlags, modules []core.Module) error {
	dir := flags.OutputPath
	if dir == "" {
		dir = fmt.Sprintf("ferrum-output-%s", time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	console := output.NewConsoleLogger(os.Stdout, flags.Verbose, flags.Quiet)
	console.Info("Writing per-module reports to " + dir)

	for _, module := range modules {
		path := filepath.Join(dir, strings.ToUpper(module.Name())+".txt")
		file, err := os.Create(path)
		if err != nil {
			console.Error(fmt.Sprintf("%s: %v", module.Name(), err))
			continue
		}

		logger := output.NewDualLogger(os.Stdout, file, flags.Verbose, flags.Quiet)
		ctx := core.NewContext(logger, build)
		logger.Info("Module: " + strings.ToUpper(module.Name()))
		if err := module.Run(ctx); err != nil {
			logger.Error(fmt.Sprintf("%s: %v", module.Name(), err))
		}
		_ = file.Close()
	}

	console.Info("Completed --ALL report directory: " + dir)
	return nil
}

func ensureParent(path string) error {
	parent := filepath.Dir(path)
	if parent == "." || parent == "" {
		return nil
	}
	return os.MkdirAll(parent, 0755)
}

func printHelp(modules []core.Module) {
	fmt.Println("Usage:")
	fmt.Println("  ferrum.exe [module] [options]")
	fmt.Println("  ferrum.exe --ALL --VERBOSE")
	fmt.Println("  ferrum.exe --CLSID --OUTPUT clsid.txt")
	fmt.Println("  ferrum.exe --ALL --OUTPUT ferrum-reports")
	fmt.Println()
	fmt.Println("Modules:")
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Name() < modules[j].Name()
	})
	width := 0
	for _, module := range modules {
		flag := displayFlag(module.Name())
		if len(flag) > width {
			width = len(flag)
		}
	}
	for _, module := range modules {
		fmt.Printf("  %-*s %s\n", width+2, displayFlag(module.Name()), module.Description())
	}
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --VERBOSE       Include additional context")
	fmt.Println("  --QUIET         Suppress banner and informational output")
	fmt.Println("  --ALL           Run every registered module")
	fmt.Println("  --OUTPUT FILE   Write a report file; with --ALL, use/create a report folder")
	fmt.Println("  --HELP          Show this help")
}

func displayFlag(name string) string {
	return "--" + strings.ToUpper(name)
}
