//go:build windows

package services

import (
	"fmt"
	"sort"
	"syscall"
	"unsafe"

	wintypes "ferrum/windows/types"
)

const (
	scManagerEnumerateService = 0x0004
	serviceQueryConfig        = 0x0001
	serviceWin32              = 0x00000030
	serviceDriver             = 0x0000000b
	serviceStateAll           = 0x00000003
	scEnumProcessInfo         = 0

	serviceBootStart   = 0
	serviceSystemStart = 1
	serviceAutoStart   = 2
	serviceDemandStart = 3
	serviceDisabled    = 4
)

type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

type enumServiceStatusProcess struct {
	ServiceName *uint16
	DisplayName *uint16
	Status      serviceStatusProcess
}

type queryServiceConfig struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagID            uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
}

type ServiceInfo = wintypes.ServiceInfo
type DriverInfo = wintypes.DriverInfo

var (
	advapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManager        = advapi32.NewProc("OpenSCManagerW")
	procEnumServicesStatusEx = advapi32.NewProc("EnumServicesStatusExW")
	procOpenService          = advapi32.NewProc("OpenServiceW")
	procQueryServiceConfig   = advapi32.NewProc("QueryServiceConfigW")
	procCloseServiceHandle   = advapi32.NewProc("CloseServiceHandle")
)

func EnumerateServices() ([]ServiceInfo, error) {
	services, err := enumerateSCM(serviceWin32)
	if err != nil {
		return nil, err
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services, nil
}

func EnumerateDrivers() ([]DriverInfo, error) {
	services, err := enumerateSCM(serviceDriver)
	if err != nil {
		return nil, err
	}
	drivers := make([]DriverInfo, 0, len(services))
	for _, service := range services {
		drivers = append(drivers, DriverInfo{
			Name:       service.Name,
			State:      service.State,
			StartType:  service.StartType,
			BinaryPath: service.BinaryPath,
		})
	}
	sort.Slice(drivers, func(i, j int) bool { return drivers[i].Name < drivers[j].Name })
	return drivers, nil
}

func enumerateSCM(serviceType uint32) ([]ServiceInfo, error) {
	manager, _, err := procOpenSCManager.Call(0, 0, scManagerEnumerateService)
	if manager == 0 {
		return nil, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer procCloseServiceHandle.Call(manager)

	var needed uint32
	var count uint32
	var resume uint32
	procEnumServicesStatusEx.Call(manager, scEnumProcessInfo, uintptr(serviceType), serviceStateAll, 0, 0, uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&resume)), 0)
	if needed == 0 {
		return nil, nil
	}

	buffer := make([]byte, needed)
	ret, _, err := procEnumServicesStatusEx.Call(manager, scEnumProcessInfo, uintptr(serviceType), serviceStateAll, uintptr(unsafe.Pointer(&buffer[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&resume)), 0)
	if ret == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx: %w", err)
	}

	items := make([]ServiceInfo, 0, count)
	base := uintptr(unsafe.Pointer(&buffer[0]))
	itemSize := unsafe.Sizeof(enumServiceStatusProcess{})
	for i := uint32(0); i < count; i++ {
		entry := (*enumServiceStatusProcess)(unsafe.Pointer(base + uintptr(i)*itemSize))
		info := ServiceInfo{
			Name:        utf16PtrToString(entry.ServiceName),
			DisplayName: utf16PtrToString(entry.DisplayName),
			State:       serviceStateName(entry.Status.CurrentState),
			ProcessID:   entry.Status.ProcessID,
			ServiceType: entry.Status.ServiceType,
		}
		if cfg, err := queryService(manager, info.Name); err == nil {
			info.StartType = serviceStartName(cfg.StartType)
			info.Account = utf16PtrToString(cfg.ServiceStartName)
			info.BinaryPath = utf16PtrToString(cfg.BinaryPathName)
			if info.DisplayName == "" {
				info.DisplayName = utf16PtrToString(cfg.DisplayName)
			}
		}
		items = append(items, info)
	}
	return items, nil
}

func queryService(manager uintptr, name string) (queryServiceConfig, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return queryServiceConfig{}, err
	}
	service, _, err := procOpenService.Call(manager, uintptr(unsafe.Pointer(namePtr)), serviceQueryConfig)
	if service == 0 {
		return queryServiceConfig{}, err
	}
	defer procCloseServiceHandle.Call(service)

	var needed uint32
	procQueryServiceConfig.Call(service, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return queryServiceConfig{}, fmt.Errorf("QueryServiceConfig: no buffer size")
	}
	buffer := make([]byte, needed)
	ret, _, err := procQueryServiceConfig.Call(service, uintptr(unsafe.Pointer(&buffer[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if ret == 0 {
		return queryServiceConfig{}, err
	}
	return *(*queryServiceConfig)(unsafe.Pointer(&buffer[0])), nil
}

func serviceStateName(state uint32) string {
	switch state {
	case 1:
		return "Stopped"
	case 2:
		return "StartPending"
	case 3:
		return "StopPending"
	case 4:
		return "Running"
	case 5:
		return "ContinuePending"
	case 6:
		return "PausePending"
	case 7:
		return "Paused"
	default:
		return fmt.Sprintf("State:%d", state)
	}
}

func serviceStartName(start uint32) string {
	switch start {
	case serviceBootStart:
		return "Boot"
	case serviceSystemStart:
		return "System"
	case serviceAutoStart:
		return "Auto"
	case serviceDemandStart:
		return "Manual"
	case serviceDisabled:
		return "Disabled"
	default:
		return fmt.Sprintf("Start:%d", start)
	}
}

func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	var values []uint16
	for p := uintptr(unsafe.Pointer(ptr)); ; p += unsafe.Sizeof(*ptr) {
		value := *(*uint16)(unsafe.Pointer(p))
		if value == 0 {
			break
		}
		values = append(values, value)
	}
	return syscall.UTF16ToString(values)
}
