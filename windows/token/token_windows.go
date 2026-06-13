//go:build windows

package token

import (
	"fmt"
	"sort"
	"syscall"
	"unsafe"

	wintypes "ferrum/windows/types"
)

const (
	processQueryLimitedInformation = 0x1000
	tokenQuery                     = 0x0008

	tokenUser            = 1
	tokenPrivilegesClass = 3
	tokenElevation       = 20
	tokenIntegrity       = 25

	securityMandatoryUntrustedRID = 0x00000000
	securityMandatoryLowRID       = 0x00001000
	securityMandatoryMediumRID    = 0x00002000
	securityMandatoryHighRID      = 0x00003000
	securityMandatorySystemRID    = 0x00004000

	sePrivilegeEnabled = 0x00000002
)

type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}

type tokenUserStruct struct {
	User sidAndAttributes
}

type tokenMandatoryLabel struct {
	Label sidAndAttributes
}

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

type tokenPrivilegesHeader struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

type tokenElevationStruct struct {
	TokenIsElevated uint32
}

type TokenInfo = wintypes.TokenInfo

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcess           = kernel32.NewProc("OpenProcess")
	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation   = advapi32.NewProc("GetTokenInformation")
	procConvertSidToStringSid = advapi32.NewProc("ConvertSidToStringSidW")
	procLookupAccountSid      = advapi32.NewProc("LookupAccountSidW")
	procLookupPrivilegeName   = advapi32.NewProc("LookupPrivilegeNameW")
	procLocalFree             = kernel32.NewProc("LocalFree")
	procGetLengthSid          = advapi32.NewProc("GetLengthSid")
	procGetSidSubAuthority    = advapi32.NewProc("GetSidSubAuthority")
	procGetSidSubAuthorityCnt = advapi32.NewProc("GetSidSubAuthorityCount")
	procCloseHandle           = kernel32.NewProc("CloseHandle")
)

func InspectProcessToken(pid uint32) (TokenInfo, error) {
	process, _, err := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if process == 0 {
		return TokenInfo{}, fmt.Errorf("open process: %w", err)
	}
	defer procCloseHandle.Call(process)

	var token uintptr
	ret, _, err := procOpenProcessToken.Call(process, tokenQuery, uintptr(unsafe.Pointer(&token)))
	if ret == 0 {
		return TokenInfo{}, fmt.Errorf("open token: %w", err)
	}
	defer procCloseHandle.Call(token)

	info := TokenInfo{}
	if user, err := tokenUserName(token); err == nil {
		info.User = user
	}
	if elevated, err := tokenElevated(token); err == nil {
		info.Elevated = elevated
	}
	if integrity, err := tokenIntegrityLevel(token); err == nil {
		info.Integrity = integrity
	}
	if privileges, err := tokenPrivileges(token); err == nil {
		info.Privileges = privileges
	}
	return info, nil
}

func tokenUserName(token uintptr) (string, error) {
	buffer, err := tokenInfoBuffer(token, tokenUser)
	if err != nil {
		return "", err
	}
	user := (*tokenUserStruct)(unsafe.Pointer(&buffer[0]))
	if name := lookupAccount(user.User.Sid); name != "" {
		return name, nil
	}
	return sidString(user.User.Sid)
}

func tokenElevated(token uintptr) (bool, error) {
	buffer, err := tokenInfoBuffer(token, tokenElevation)
	if err != nil {
		return false, err
	}
	elevation := (*tokenElevationStruct)(unsafe.Pointer(&buffer[0]))
	return elevation.TokenIsElevated != 0, nil
}

func tokenIntegrityLevel(token uintptr) (string, error) {
	buffer, err := tokenInfoBuffer(token, tokenIntegrity)
	if err != nil {
		return "", err
	}
	label := (*tokenMandatoryLabel)(unsafe.Pointer(&buffer[0]))
	rid := sidLastSubAuthority(label.Label.Sid)
	switch {
	case rid >= securityMandatorySystemRID:
		return "System", nil
	case rid >= securityMandatoryHighRID:
		return "High", nil
	case rid >= securityMandatoryMediumRID:
		return "Medium", nil
	case rid >= securityMandatoryLowRID:
		return "Low", nil
	case rid >= securityMandatoryUntrustedRID:
		return "Untrusted", nil
	default:
		return "Unknown", nil
	}
}

func tokenPrivileges(token uintptr) ([]string, error) {
	buffer, err := tokenInfoBuffer(token, tokenPrivilegesClass)
	if err != nil {
		return nil, err
	}
	header := (*tokenPrivilegesHeader)(unsafe.Pointer(&buffer[0]))
	count := int(header.PrivilegeCount)
	base := uintptr(unsafe.Pointer(&header.Privileges[0]))
	size := unsafe.Sizeof(luidAndAttributes{})
	names := make([]string, 0, count)
	for i := 0; i < count; i++ {
		item := (*luidAndAttributes)(unsafe.Pointer(base + uintptr(i)*size))
		if item.Attributes&sePrivilegeEnabled == 0 {
			continue
		}
		if name := lookupPrivilege(item.Luid); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func tokenInfoBuffer(token uintptr, class uint32) ([]byte, error) {
	var needed uint32
	procGetTokenInformation.Call(token, uintptr(class), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil, fmt.Errorf("GetTokenInformation(%d): no buffer size", class)
	}
	buffer := make([]byte, needed)
	ret, _, err := procGetTokenInformation.Call(token, uintptr(class), uintptr(unsafe.Pointer(&buffer[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if ret == 0 {
		return nil, fmt.Errorf("GetTokenInformation(%d): %w", class, err)
	}
	return buffer, nil
}

func lookupAccount(sid uintptr) string {
	var nameLen uint32
	var domainLen uint32
	var sidType uint32
	procLookupAccountSid.Call(0, sid, 0, uintptr(unsafe.Pointer(&nameLen)), 0, uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&sidType)))
	if nameLen == 0 {
		return ""
	}
	name := make([]uint16, nameLen)
	domain := make([]uint16, domainLen)
	ret, _, _ := procLookupAccountSid.Call(0, sid, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)), uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&sidType)))
	if ret == 0 {
		return ""
	}
	n := syscall.UTF16ToString(name)
	d := syscall.UTF16ToString(domain)
	if d != "" {
		return d + `\` + n
	}
	return n
}

func sidString(sid uintptr) (string, error) {
	var out uintptr
	ret, _, err := procConvertSidToStringSid.Call(sid, uintptr(unsafe.Pointer(&out)))
	if ret == 0 {
		return "", err
	}
	defer procLocalFree.Call(out)
	return utf16PtrToString((*uint16)(unsafe.Pointer(out))), nil
}

func lookupPrivilege(id luid) string {
	var nameLen uint32
	procLookupPrivilegeName.Call(0, uintptr(unsafe.Pointer(&id)), 0, uintptr(unsafe.Pointer(&nameLen)))
	if nameLen == 0 {
		return ""
	}
	name := make([]uint16, nameLen+1)
	ret, _, _ := procLookupPrivilegeName.Call(0, uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)))
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(name)
}

func sidLastSubAuthority(sid uintptr) uint32 {
	countPtr, _, _ := procGetSidSubAuthorityCnt.Call(sid)
	if countPtr == 0 {
		return 0
	}
	count := *(*byte)(unsafe.Pointer(countPtr))
	if count == 0 {
		return 0
	}
	ridPtr, _, _ := procGetSidSubAuthority.Call(sid, uintptr(count-1))
	if ridPtr == 0 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(ridPtr))
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
