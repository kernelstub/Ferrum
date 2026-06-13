package startup

import (
	"fmt"
	"strings"

	"ferrum/core"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "startup" }

func (Module) Description() string {
	return "Inspect Run keys and Startup folders for persistence surface"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Enumerating startup persistence locations...")
	entries, err := win.EnumerateStartupEntries()
	if err != nil {
		return err
	}
	ctx.Logger.Info(fmt.Sprintf("Startup entries enumerated: %d", len(entries)))
	if len(entries) == 0 {
		ctx.Logger.Info("No startup entries found in common locations.")
		return nil
	}
	for _, entry := range entries {
		ctx.Logger.Verbose(fmt.Sprintf("startup inventory : scope=%s location=%s name=%s command=%s", entry.Scope, entry.Location, entry.Name, entry.Command))
		ctx.Logger.Success(fmt.Sprintf("%s\\%s > %s", entry.Scope, entry.Name, startupReason(entry.Command)))
		ctx.Logger.Verbose(fmt.Sprintf("%s : %s", entry.Location, entry.Command))
	}
	return nil
}

func startupReason(command string) string {
	lower := strings.ToLower(command)
	switch {
	case strings.Contains(lower, `\users\`) || strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\programdata\`):
		return "user-writable-looking command"
	case strings.Contains(lower, "powershell") || strings.Contains(lower, "wscript") || strings.Contains(lower, "cscript") || strings.Contains(lower, "cmd.exe"):
		return "script interpreter startup"
	default:
		return "startup entry"
	}
}
