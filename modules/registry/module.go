package registry

import (
	"fmt"

	"ferrum/core"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "registry" }

func (Module) Description() string {
	return "Audit sensitive registry persistence, policy, and interception surfaces"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Auditing sensitive registry surfaces...")
	findings, err := win.EnumerateRegistryAuditFindings()
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		ctx.Logger.Info("No sensitive registry findings matched the configured checks.")
		return nil
	}
	for _, finding := range findings {
		ctx.Logger.Success(fmt.Sprintf("%s %s\\%s > %s: %s", finding.Severity, finding.Scope, finding.Path, finding.Name, finding.Reason))
		if finding.Value != "" {
			ctx.Logger.Verbose(fmt.Sprintf("%s\\%s\\%s = %s", finding.Scope, finding.Path, finding.Name, finding.Value))
		}
	}
	return nil
}
