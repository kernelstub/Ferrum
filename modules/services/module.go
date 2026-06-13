package services

import (
	"fmt"
	"strings"

	"ferrum/core"
	"ferrum/internal"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "services" }

func (Module) Description() string {
	return "Inventory Windows services and highlight audit-worthy configuration"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Enumerating Windows services...")
	services, err := win.EnumerateServices()
	if err != nil {
		return err
	}
	reported := 0
	for _, service := range services {
		reasons := serviceReasons(service)
		if len(reasons) == 0 {
			continue
		}
		reported++
		ctx.Logger.Success(fmt.Sprintf("%s > %s", service.Name, strings.Join(reasons, ", ")))
		ctx.Logger.Verbose(fmt.Sprintf("%s : state=%s start=%s account=%s pid=%d path=%s", service.Name, service.State, service.StartType, service.Account, service.ProcessID, service.BinaryPath))
	}
	if reported == 0 {
		ctx.Logger.Info("No service configuration stood out from the default heuristics.")
	}
	ctx.Logger.Verbose(fmt.Sprintf("Services enumerated: %d", len(services)))
	return nil
}

func serviceReasons(service win.ServiceInfo) []string {
	reasons := []string{}
	path := strings.TrimSpace(service.BinaryPath)
	lowerPath := strings.ToLower(path)
	if service.State == "Running" && service.Account != "" && !strings.Contains(strings.ToLower(service.Account), "localsystem") {
		reasons = append(reasons, "non-System running account")
	}
	if isUnquotedPathWithSpaces(path) {
		reasons = append(reasons, "unquoted path with spaces")
	}
	if strings.Contains(lowerPath, `\users\`) || strings.Contains(lowerPath, `\temp\`) || strings.Contains(lowerPath, `\programdata\`) {
		reasons = append(reasons, "user-writable-looking path")
	}
	if service.StartType == "Auto" && service.State != "Running" {
		reasons = append(reasons, "auto-start not running")
	}
	return internal.Limit(reasons, 4)
}

func isUnquotedPathWithSpaces(path string) bool {
	path = strings.TrimSpace(path)
	return strings.Contains(path, " ") && !strings.HasPrefix(path, `"`)
}
