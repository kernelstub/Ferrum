package tokens

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"ferrum/core"
	"ferrum/internal"
	win "ferrum/windows/facade"
)

func init() { core.Register(Module{}) }

type Module struct{}

func (Module) Name() string { return "tokens" }

func (Module) Description() string {
	return "Hunt process tokens with sensitive privileges and elevated integrity"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Enumerating process tokens and sensitive privileges...")
	processes, err := win.EnumerateProcesses()
	if err != nil {
		return err
	}
	findings := inspect(processes)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		return findings[i].Name < findings[j].Name
	})
	reported := 0
	for _, finding := range findings {
		if finding.Score == 0 {
			continue
		}
		reported++
		ctx.Logger.Success(fmt.Sprintf("%s[%d] > %s", finding.Name, finding.PID, strings.Join(finding.Reasons, ", ")))
		ctx.Logger.Verbose(fmt.Sprintf("%s[%d] : %s privileges=%s", finding.Name, finding.PID, finding.Process.Label(), strings.Join(internal.Limit(finding.Privileges, 12), ",")))
	}
	if reported == 0 {
		ctx.Logger.Info("No accessible process tokens matched the sensitive privilege heuristics.")
	}
	ctx.Logger.Verbose(fmt.Sprintf("Processes inspected: %d", len(processes)))
	return nil
}

type tokenFinding struct {
	win.Process
	Reasons []string
	Score   int
}

func inspect(processes []win.Process) []tokenFinding {
	workers := runtime.NumCPU()
	if workers > 16 {
		workers = 16
	}
	jobs := make(chan win.Process)
	results := make(chan tokenFinding, len(processes))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for process := range jobs {
				token, err := win.InspectProcessToken(process.PID)
				finding := tokenFinding{Process: process}
				if err == nil {
					finding.User = token.User
					finding.Integrity = token.Integrity
					finding.Elevated = token.Elevated
					finding.Privileges = token.Privileges
					finding.Reasons, finding.Score = tokenReasons(token)
				}
				results <- finding
			}
		}()
	}
	go func() {
		for _, process := range processes {
			jobs <- process
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	findings := make([]tokenFinding, 0, len(processes))
	for finding := range results {
		findings = append(findings, finding)
	}
	return findings
}

func tokenReasons(token win.TokenInfo) ([]string, int) {
	score := 0
	reasons := []string{}
	if token.Elevated {
		reasons = append(reasons, "elevated token")
		score += 20
	}
	if token.Integrity == "System" || token.Integrity == "High" {
		reasons = append(reasons, token.Integrity+" integrity")
		score += 15
	}
	interesting := map[string]int{
		"SeDebugPrivilege":                40,
		"SeImpersonatePrivilege":          35,
		"SeAssignPrimaryTokenPrivilege":   35,
		"SeTcbPrivilege":                  45,
		"SeBackupPrivilege":               25,
		"SeRestorePrivilege":              25,
		"SeLoadDriverPrivilege":           35,
		"SeCreateTokenPrivilege":          45,
		"SeTakeOwnershipPrivilege":        20,
		"SeManageVolumePrivilege":         20,
		"SeTrustedCredManAccessPrivilege": 40,
		"SeRelabelPrivilege":              30,
		"SeCreateGlobalPrivilege":         10,
	}
	for _, privilege := range token.Privileges {
		if points, ok := interesting[privilege]; ok {
			reasons = append(reasons, privilege)
			score += points
		}
	}
	return internal.Limit(reasons, 8), score
}
