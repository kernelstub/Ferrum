package clsid

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"ferrum/core"
	win "ferrum/windows/facade"
)

const maxProcessWorkers = 16

func init() {
	core.Register(Module{})
}

type Module struct{}

func (Module) Name() string {
	return "clsid"
}

func (Module) Description() string {
	return "Correlate privileged processes with HKCU COM registration surface"
}

func (Module) Run(ctx *core.Context) error {
	ctx.Logger.Info("Applying ProcMon-style CLSID filters: User is NT AUTHORITY\\SYSTEM; Path contains HKCU\\Software\\Classes; Path contains InprocServer32 or LocalServer32; Result is NAME NOT FOUND.")
	ctx.Logger.Info("Enumerating running processes...")
	processes, err := win.EnumerateProcesses()
	if err != nil {
		return err
	}

	ctx.Logger.Info("Inspecting process security context...")
	enriched := enrichProcesses(ctx, processes)
	sortProcesses(enriched)
	ctx.Logger.Info(fmt.Sprintf("Processes enumerated: %d", len(enriched)))

	interesting := 0
	for _, process := range enriched {
		status := "process"
		if process.Interesting {
			interesting++
			status = "privileged/elevated process"
		}
		ctx.Logger.Success(fmt.Sprintf("%s[%d] > %s > %s", process.Name, process.PID, status, process.Label()))
		if process.Detail != "" {
			ctx.Logger.Verbose(fmt.Sprintf("%s[%d] : %s", process.Name, process.PID, process.Detail))
		}
	}
	if interesting == 0 {
		ctx.Logger.Info("No privileged or elevated processes identified from accessible token data.")
	}

	ctx.Logger.Info("Scanning HKLM COM registrations for missing HKCU InprocServer32/LocalServer32 lookups...")
	candidates, err := win.EnumerateCLSIDProcMonCandidates()
	if err != nil {
		ctx.Logger.Error(fmt.Sprintf("CLSID ProcMon candidate scan: %v", err))
	} else {
		ctx.Logger.Info(fmt.Sprintf("CLSID ProcMon candidates: %d", len(candidates)))
		reportProcMonCandidates(ctx, candidates, interestingProcesses(enriched))
	}

	ctx.Logger.Info("Inspecting HKCU\\Software\\Classes\\CLSID...")
	entries, err := win.EnumerateHKCUCLSID()
	if err != nil {
		ctx.Logger.Error(fmt.Sprintf("HKCU CLSID enumeration: %v", err))
		return nil
	}

	if len(entries) == 0 {
		ctx.Logger.Info("No HKCU CLSID registrations found.")
		return nil
	}
	ctx.Logger.Info(fmt.Sprintf("HKCU CLSID values enumerated: %d", len(entries)))

	for _, entry := range summarizeCLSID(entries) {
		name := entry.Name
		if name == "" {
			name = "(Default)"
		}
		ctx.Logger.Success(fmt.Sprintf("%s > %s > %s", entry.Path, name, entry.Kind))
		if entry.Value != "" {
			ctx.Logger.Verbose(fmt.Sprintf("%s : type=%d value=%s", entry.CLSID, entry.Type, entry.Value))
		}
	}

	if interesting > 0 {
		ctx.Logger.Info("Privileged COM clients commonly search HKCU before HKLM for per-user COM classes; review user-controlled registrations above for unusual or hijack-prone behavior.")
	}
	return nil
}

func reportProcMonCandidates(ctx *core.Context, candidates []win.CLSIDProcMonCandidate, processes []processFinding) {
	if len(candidates) == 0 {
		ctx.Logger.Info("No HKCU COM NAME NOT FOUND candidates found for InprocServer32 or LocalServer32.")
		return
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Kind != candidates[j].Kind {
			return candidates[i].Kind < candidates[j].Kind
		}
		return candidates[i].CLSID < candidates[j].CLSID
	})

	processLabel := "NT AUTHORITY\\SYSTEM / privileged COM client"
	if len(processes) > 0 {
		names := make([]string, 0, len(processes))
		for _, process := range processes {
			names = append(names, fmt.Sprintf("%s[%d]", process.Name, process.PID))
		}
		processLabel = fmt.Sprintf("%d privileged/elevated process(es)", len(processes))
		ctx.Logger.Info("Privileged/elevated process set: " + strings.Join(names, ", "))
	}

	for _, candidate := range candidates {
		ctx.Logger.Success(fmt.Sprintf("%s > %s > %s", processLabel, candidate.Path, candidate.Result))
		ctx.Logger.Verbose(fmt.Sprintf("%s : CLSID=%s machine=%s", candidate.Kind, candidate.CLSID, candidate.MachineValue))
	}
	ctx.Logger.Info("These rows model the ProcMon filter Result=NAME NOT FOUND for HKCU COM override paths. Confirm live process access with ProcMon or ETW before treating a candidate as reachable.")
}

func interestingProcesses(processes []processFinding) []processFinding {
	out := make([]processFinding, 0)
	for _, process := range processes {
		if process.Interesting {
			out = append(out, process)
		}
	}
	return out
}

type processFinding struct {
	win.Process
	Interesting bool
	Priority    int
	Detail      string
}

func enrichProcesses(ctx *core.Context, processes []win.Process) []processFinding {
	workers := runtime.NumCPU()
	if workers > maxProcessWorkers {
		workers = maxProcessWorkers
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan win.Process)
	results := make(chan processFinding, len(processes))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for process := range jobs {
				finding := processFinding{Process: process}
				token, err := win.InspectProcessToken(process.PID)
				if err != nil {
					finding.Detail = err.Error()
					if strings.Contains(strings.ToLower(err.Error()), "access") {
						ctx.Logger.Verbose(fmt.Sprintf("%s[%d] : %v", process.Name, process.PID, err))
					}
					results <- finding
					continue
				}

				finding.User = token.User
				finding.Integrity = token.Integrity
				finding.Elevated = token.Elevated
				finding.Privileges = token.Privileges
				finding.Interesting, finding.Priority, finding.Detail = classify(token)
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

	findings := make([]processFinding, 0, len(processes))
	for finding := range results {
		findings = append(findings, finding)
	}
	return findings
}

func classify(token win.TokenInfo) (bool, int, string) {
	user := strings.ToUpper(token.User)
	switch {
	case strings.HasSuffix(user, `\SYSTEM`) || strings.EqualFold(token.User, "SYSTEM"):
		return true, 100, detail(token)
	case strings.HasSuffix(user, `\LOCAL SERVICE`) || strings.HasSuffix(user, `\LOCALSERVICE`):
		return true, 90, detail(token)
	case strings.HasSuffix(user, `\NETWORK SERVICE`) || strings.HasSuffix(user, `\NETWORKSERVICE`):
		return true, 80, detail(token)
	case token.Elevated:
		return true, 70, detail(token)
	default:
		return false, 0, detail(token)
	}
}

func detail(token win.TokenInfo) string {
	parts := []string{}
	if token.User != "" {
		parts = append(parts, "user="+token.User)
	}
	if token.Integrity != "" {
		parts = append(parts, "integrity="+token.Integrity)
	}
	if token.Elevated {
		parts = append(parts, "elevated=true")
	}
	if len(token.Privileges) > 0 {
		parts = append(parts, "privileges="+strings.Join(token.Privileges, ","))
	}
	return strings.Join(parts, " ")
}

func sortProcesses(processes []processFinding) {
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].Priority != processes[j].Priority {
			return processes[i].Priority > processes[j].Priority
		}
		return strings.ToLower(processes[i].Name) < strings.ToLower(processes[j].Name)
	})
}

func summarizeCLSID(entries []win.CLSIDEntry) []win.CLSIDEntry {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CLSID != entries[j].CLSID {
			return entries[i].CLSID < entries[j].CLSID
		}
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}
