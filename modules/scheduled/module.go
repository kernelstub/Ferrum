package scheduled

import (
	"fmt"
	"strings"

	"ferrum/core"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "scheduled" }

func (Module) Description() string {
	return "Inspect scheduled task XML for interesting execution paths"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Enumerating scheduled tasks...")
	tasks, err := win.EnumerateScheduledTasks()
	if err != nil {
		return err
	}
	ctx.Logger.Info(fmt.Sprintf("Scheduled tasks enumerated: %d", len(tasks)))
	reported := 0
	for _, task := range tasks {
		ctx.Logger.Verbose(fmt.Sprintf("task inventory : path=%s enabled=%s author=%s command=%s", task.Path, task.Enabled, task.Author, task.Command))
		reason := taskReason(task)
		if reason == "" {
			continue
		}
		reported++
		ctx.Logger.Success(fmt.Sprintf("%s > %s", task.Path, reason))
		ctx.Logger.Verbose(fmt.Sprintf("%s : enabled=%s author=%s command=%s", task.Path, task.Enabled, task.Author, task.Command))
	}
	if reported == 0 {
		ctx.Logger.Info("No scheduled tasks matched the default interesting-command heuristics.")
	}
	return nil
}

func taskReason(task win.ScheduledTask) string {
	lower := strings.ToLower(task.Command)
	switch {
	case task.Command == "":
		return ""
	case strings.Contains(lower, `\users\`) || strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\programdata\`):
		return "user-writable-looking task command"
	case strings.Contains(lower, "powershell") || strings.Contains(lower, "wscript") || strings.Contains(lower, "cscript") || strings.Contains(lower, "rundll32") || strings.Contains(lower, "regsvr32"):
		return "script or LOLBin task command"
	case strings.EqualFold(task.Enabled, "false"):
		return "disabled task with execution action"
	default:
		return ""
	}
}
