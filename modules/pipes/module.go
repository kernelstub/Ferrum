package pipes

import (
	"fmt"
	"strings"

	"ferrum/core"
	"ferrum/internal"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "pipes" }

func (Module) Description() string {
	return "Enumerate named pipes and flag security-relevant pipe names"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Enumerating named pipes...")
	pipes, err := win.EnumerateNamedPipes()
	if err != nil {
		return err
	}
	reported := 0
	for _, pipe := range pipes {
		reason := pipeReason(pipe.Name)
		if reason == "" {
			continue
		}
		reported++
		ctx.Logger.Success(fmt.Sprintf("%s > %s", pipe.Name, reason))
	}
	ctx.Logger.Verbose(fmt.Sprintf("Pipes enumerated: %d", len(pipes)))
	for _, pipe := range internal.Limit(pipes, 50) {
		ctx.Logger.Verbose(fmt.Sprintf("pipe : %s", pipe.Name))
	}
	if reported == 0 {
		ctx.Logger.Info("No named pipes matched the default high-signal name heuristics.")
	}
	return nil
}

func pipeReason(name string) string {
	lower := strings.ToLower(name)
	keywords := []string{"svc", "service", "rpc", "spool", "lsass", "samr", "netlogon", "winreg", "atsvc", "epmapper", "browser"}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return "security-relevant IPC surface"
		}
	}
	return ""
}
