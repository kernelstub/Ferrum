package dllsearch

import (
	"fmt"

	"ferrum/core"
	"ferrum/internal"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "dllsearch" }

func (Module) Description() string {
	return "Analyze DLL search path and KnownDLL context for hijack-prone surface"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Analyzing DLL search path surface...")
	findings, err := win.EnumerateDLLSearchPathFindings()
	if err != nil {
		return err
	}
	reported := 0
	for _, finding := range findings {
		if finding.Severity == "Info" {
			ctx.Logger.Verbose(fmt.Sprintf("%s %s > %s", finding.Source, finding.Path, finding.Reason))
			continue
		}
		reported++
		ctx.Logger.Success(fmt.Sprintf("%s %s > %s", finding.Severity, finding.Source, finding.Reason))
		ctx.Logger.Verbose(fmt.Sprintf("%s : %s", finding.Source, finding.Path))
	}
	if reported == 0 {
		ctx.Logger.Info("No risky DLL search path entries matched the default heuristics.")
	}
	for _, finding := range internal.Limit(findings, 40) {
		if finding.Severity == "Info" {
			ctx.Logger.Verbose(fmt.Sprintf("KnownDLL : %s", finding.Path))
		}
	}
	return nil
}
