//go:build windows

package process

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	th32csSnapProcess = 0x00000002
	maxPath           = 260
)

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
}

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snap = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW      = kernel32.NewProc("Process32FirstW")
	procProcess32NextW       = kernel32.NewProc("Process32NextW")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
)

func EnumerateProcesses() ([]Process, error) {
	snapshot, _, err := procCreateToolhelp32Snap.Call(th32csSnapProcess, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer procCloseHandle.Call(snapshot)

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, err := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32FirstW: %w", err)
	}

	processes := make([]Process, 0, 256)
	for {
		processes = append(processes, Process{
			PID:       entry.ProcessID,
			ParentPID: entry.ParentProcessID,
			Name:      syscall.UTF16ToString(entry.ExeFile[:]),
		})
		ret, _, err = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_NO_MORE_FILES {
				break
			}
			break
		}
	}
	return processes, nil
}
