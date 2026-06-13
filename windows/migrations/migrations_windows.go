//go:build windows

package migrations

import (
	"fmt"
	"sort"
	"syscall"
	"unsafe"

	winprocess "ferrum/windows/process"
)

const (
	processDEPPolicy        = 0
	processASLRPolicy       = 1
	processStrictHandle     = 2
	processControlFlowGuard = 7
)

type mitigationFlags struct {
	Flags uint32
}

var procGetProcessMitigationPolicy = kernel32.NewProc("GetProcessMitigationPolicy")

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess = kernel32.NewProc("OpenProcess")
	procCloseHandle = kernel32.NewProc("CloseHandle")
)

type ProcessMitigation = winprocess.ProcessMitigation

const processQueryLimitedInformation = 0x1000

func EnumerateProcessMitigations() ([]ProcessMitigation, error) {
	processes, err := winprocess.EnumerateProcesses()
	if err != nil {
		return nil, err
	}
	results := make([]ProcessMitigation, 0, len(processes))
	for _, process := range processes {
		handle, _, err := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(process.PID))
		if handle == 0 {
			results = append(results, ProcessMitigation{Process: process, DEP: fmt.Sprintf("open: %v", err)})
			continue
		}
		item := ProcessMitigation{Process: process}
		item.DEP = mitigationValue(handle, processDEPPolicy)
		item.ASLR = mitigationValue(handle, processASLRPolicy)
		item.Strict = mitigationValue(handle, processStrictHandle)
		item.CFG = mitigationValue(handle, processControlFlowGuard)
		procCloseHandle.Call(handle)
		results = append(results, item)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return results, nil
}

func mitigationValue(handle uintptr, policy uintptr) string {
	var flags mitigationFlags
	ret, _, err := procGetProcessMitigationPolicy.Call(handle, policy, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags))
	if ret == 0 {
		return fmt.Sprintf("error:%v", err)
	}
	if flags.Flags == 0 {
		return "off"
	}
	return fmt.Sprintf("0x%08x", flags.Flags)
}
