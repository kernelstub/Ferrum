package policy

import (
	"fmt"

	"ferrum/core"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "policy" }

func (Module) Description() string {
	return "Summarize hardening policy posture such as UAC, AppLocker, and WDAC"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Checking hardening policy posture...")
	findings, err := win.EnumeratePolicyFindings()
	if err != nil {
		return err
	}
	ctx.Logger.Info(fmt.Sprintf("Policy checks returned: %d", len(findings)))
	for _, finding := range findings {
		ctx.Logger.Success(fmt.Sprintf("%s %s > %s", finding.Severity, finding.Name, finding.Reason))
		ctx.Logger.Verbose(fmt.Sprintf("%s = %s", finding.Name, finding.Value))
	}
	if len(findings) == 0 {
		ctx.Logger.Info("No policy findings returned from configured checks.")
	}
	return nil
}
