package drivers

import (
	"fmt"
	"strings"

	"ferrum/core"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "drivers" }

func (Module) Description() string {
	return "Enumerate kernel drivers and suspicious driver load paths"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Enumerating kernel driver services...")
	drivers, err := win.EnumerateDrivers()
	if err != nil {
		return err
	}
	reported := 0
	for _, driver := range drivers {
		reason := driverReason(driver)
		if reason == "" {
			continue
		}
		reported++
		ctx.Logger.Success(fmt.Sprintf("%s > %s", driver.Name, reason))
		ctx.Logger.Verbose(fmt.Sprintf("%s : state=%s start=%s path=%s", driver.Name, driver.State, driver.StartType, driver.BinaryPath))
	}
	if reported == 0 {
		ctx.Logger.Info("No driver load paths matched the suspicious-path heuristics.")
	}
	ctx.Logger.Verbose(fmt.Sprintf("Drivers enumerated: %d", len(drivers)))
	return nil
}

func driverReason(driver win.DriverInfo) string {
	path := strings.ToLower(driver.BinaryPath)
	switch {
	case strings.Contains(path, `\users\`) || strings.Contains(path, `\temp\`) || strings.Contains(path, `\programdata\`):
		return "driver image in user-writable-looking location"
	case driver.StartType == "Boot" || driver.StartType == "System":
		return "early-load driver"
	case driver.State == "Running":
		return "running kernel driver"
	default:
		return ""
	}
}
