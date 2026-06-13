package mitigations

import (
	"fmt"
	"strings"

	"ferrum/core"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "mitigations" }

func (Module) Description() string {
	return "Sample process mitigation policy posture for running processes"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Sampling process mitigation policies...")
	items, err := win.EnumerateProcessMitigations()
	if err != nil {
		return err
	}
	reported := 0
	for _, item := range items {
		reason := mitigationReason(item)
		if reason == "" {
			continue
		}
		reported++
		ctx.Logger.Success(fmt.Sprintf("%s[%d] > %s", item.Name, item.PID, reason))
		ctx.Logger.Verbose(fmt.Sprintf("%s[%d] : DEP=%s ASLR=%s StrictHandle=%s CFG=%s", item.Name, item.PID, item.DEP, item.ASLR, item.Strict, item.CFG))
	}
	if reported == 0 {
		ctx.Logger.Info("No accessible process mitigation gaps matched the default heuristics.")
	}
	ctx.Logger.Verbose(fmt.Sprintf("Processes sampled: %d", len(items)))
	return nil
}

func mitigationReason(item win.ProcessMitigation) string {
	values := []string{item.DEP, item.ASLR, item.Strict, item.CFG}
	for _, value := range values {
		if strings.HasPrefix(value, "error:") || strings.HasPrefix(value, "open:") {
			return ""
		}
	}
	gaps := []string{}
	if item.DEP == "off" {
		gaps = append(gaps, "DEP off")
	}
	if item.ASLR == "off" {
		gaps = append(gaps, "ASLR off")
	}
	if item.Strict == "off" {
		gaps = append(gaps, "strict handle checks off")
	}
	if item.CFG == "off" {
		gaps = append(gaps, "CFG off")
	}
	return strings.Join(gaps, ", ")
}
