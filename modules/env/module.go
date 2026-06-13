package env

import (
	"fmt"
	"strings"

	"ferrum/core"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "env" }

func (Module) Description() string {
	return "Inspect process environment variables for audit-relevant values"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Inspecting current process environment...")
	vars, err := win.EnumerateEnvironment()
	if err != nil {
		return err
	}
	for _, env := range vars {
		reason := envReason(env)
		if reason == "" {
			continue
		}
		ctx.Logger.Success(fmt.Sprintf("%s > %s", env.Name, reason))
		ctx.Logger.Verbose(fmt.Sprintf("%s=%s", env.Name, env.Value))
	}
	ctx.Logger.Verbose(fmt.Sprintf("Environment variables inspected: %d", len(vars)))
	return nil
}

func envReason(env win.EnvVar) string {
	name := strings.ToUpper(env.Name)
	value := strings.ToLower(env.Value)
	switch {
	case name == "PATH" && (strings.Contains(value, `\users\`) || strings.Contains(value, `\temp\`) || strings.Contains(value, `.`)):
		return "PATH contains user-writable-looking or relative element"
	case strings.Contains(name, "TOKEN") || strings.Contains(name, "SECRET") || strings.Contains(name, "PASSWORD") || strings.Contains(name, "KEY"):
		return "sensitive-looking variable name"
	case strings.Contains(value, `\users\`) || strings.Contains(value, `\temp\`):
		return "user-writable-looking value"
	default:
		return ""
	}
}
