//go:build windows

package registry

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	wintypes "ferrum/windows/types"
)

const (
	hkeyCurrentUser  = 0x80000001
	hkeyLocalMachine = 0x80000002
	keyRead          = 0x20019
	errorNoMoreItems = 259
)

const HkeyCurrentUser = hkeyCurrentUser
const HkeyLocalMachine = hkeyLocalMachine

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyEx    = advapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey     = advapi32.NewProc("RegCloseKey")
	procRegEnumKeyEx    = advapi32.NewProc("RegEnumKeyExW")
	procRegEnumValue    = advapi32.NewProc("RegEnumValueW")
	procRegQueryInfoKey = advapi32.NewProc("RegQueryInfoKeyW")
	procRegQueryValueEx = advapi32.NewProc("RegQueryValueExW")
)

type RegistryValue struct {
	Name  string
	Type  uint32
	Value string
}

func EnumerateHKCUCLSID() ([]CLSIDEntry, error) {
	const base = `Software\Classes\CLSID`
	root, err := openKey(hkeyCurrentUser, base)
	if err != nil {
		return nil, err
	}
	defer procRegCloseKey.Call(root)

	clsids, err := enumSubkeys(root)
	if err != nil {
		return nil, err
	}

	entries := make([]CLSIDEntry, 0)
	for _, clsid := range clsids {
		clsidPath := clsid
		walkCLSIDKey(root, base, clsid, clsidPath, &entries)
	}
	return entries, nil
}

func walkCLSIDKey(parent uintptr, base, clsid, relative string, entries *[]CLSIDEntry) {
	key, err := openKey(parent, relative)
	if err != nil {
		return
	}
	defer procRegCloseKey.Call(key)

	path := base + `\` + relative
	kind := clsidKind(relative)
	values, err := enumValues(key)
	if err == nil {
		for _, value := range values {
			*entries = append(*entries, CLSIDEntry{
				CLSID: clsid,
				Kind:  kind,
				Path:  `HKCU\` + path,
				Name:  displayRegistryName(value.Name),
				Type:  value.Type,
				Value: value.Value,
			})
		}
	}
	subkeyNames, err := enumSubkeys(key)
	if err != nil {
		return
	}
	for _, subkey := range subkeyNames {
		walkCLSIDKey(parent, base, clsid, relative+`\`+subkey, entries)
	}
}

func clsidKind(relative string) string {
	parts := strings.Split(relative, `\`)
	if len(parts) < 2 {
		return "(CLSID)"
	}
	return parts[1]
}

func displayRegistryName(name string) string {
	if name == "" {
		return "(Default)"
	}
	return name
}

func EnumerateCLSIDProcMonCandidates() ([]CLSIDProcMonCandidate, error) {
	root, err := openKey(hkeyLocalMachine, `Software\Classes\CLSID`)
	if err != nil {
		return nil, err
	}
	defer procRegCloseKey.Call(root)

	clsids, err := enumSubkeys(root)
	if err != nil {
		return nil, err
	}

	candidates := make([]CLSIDProcMonCandidate, 0)
	for _, clsid := range clsids {
		for _, kind := range []string{"InprocServer32", "LocalServer32"} {
			machineKey, err := openKey(root, clsid+`\`+kind)
			if err != nil {
				continue
			}
			value, _ := queryDefaultValue(machineKey)
			procRegCloseKey.Call(machineKey)

			userPath := `Software\Classes\CLSID\` + clsid + `\` + kind
			if keyExists(hkeyCurrentUser, userPath) {
				continue
			}

			candidates = append(candidates, CLSIDProcMonCandidate{
				CLSID:        clsid,
				Kind:         kind,
				Path:         `HKCU\` + userPath,
				Result:       "NAME NOT FOUND",
				MachineValue: value,
			})
		}
	}
	return candidates, nil
}

func openKey(parent uintptr, path string) (uintptr, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var handle uintptr
	ret, _, callErr := procRegOpenKeyEx.Call(parent, uintptr(unsafe.Pointer(pathPtr)), 0, keyRead, uintptr(unsafe.Pointer(&handle)))
	if ret != 0 {
		return 0, syscall.Errno(ret)
	}
	_ = callErr
	return handle, nil
}

func OpenKey(parent uintptr, path string) (uintptr, error) {
	return openKey(parent, path)
}

func CloseKey(key uintptr) {
	procRegCloseKey.Call(key)
}

func enumSubkeys(key uintptr) ([]string, error) {
	info, err := queryKeyInfo(key)
	if err != nil {
		return nil, err
	}
	nameCapacity := info.MaxSubKeyLen + 1
	if nameCapacity < 256 {
		nameCapacity = 256
	}
	keys := []string{}
	for index := uint32(0); ; index++ {
		name := make([]uint16, nameCapacity)
		length := uint32(len(name))
		ret, _, _ := procRegEnumKeyEx.Call(key, uintptr(index), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&length)), 0, 0, 0, 0)
		if ret == errorNoMoreItems {
			break
		}
		if ret != 0 {
			return keys, fmt.Errorf("RegEnumKeyEx: %w", syscall.Errno(ret))
		}
		keys = append(keys, syscall.UTF16ToString(name[:length]))
	}
	return keys, nil
}

func EnumSubkeys(key uintptr) ([]string, error) {
	return enumSubkeys(key)
}

func queryDefaultValue(key uintptr) (string, error) {
	var typ uint32
	var needed uint32
	ret, _, _ := procRegQueryValueEx.Call(key, 0, 0, uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&needed)))
	if ret != 0 || needed == 0 {
		return "", syscall.Errno(ret)
	}
	buffer := make([]uint16, needed/2+1)
	ret, _, _ = procRegQueryValueEx.Call(key, 0, 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&needed)))
	if ret != 0 {
		return "", syscall.Errno(ret)
	}
	return wintypes.CleanRegistryString(syscall.UTF16ToString(buffer)), nil
}

func QueryDefaultValue(key uintptr) (string, error) {
	return queryDefaultValue(key)
}

func keyExists(parent uintptr, path string) bool {
	key, err := openKey(parent, path)
	if err != nil {
		return false
	}
	procRegCloseKey.Call(key)
	return true
}

func KeyExists(parent uintptr, path string) bool {
	return keyExists(parent, path)
}

func registryValues(parent uintptr, path string) ([]RegistryValue, error) {
	key, err := openKey(parent, path)
	if err != nil {
		return nil, err
	}
	defer procRegCloseKey.Call(key)

	return enumValues(key)
}

func enumValues(key uintptr) ([]RegistryValue, error) {
	info, err := queryKeyInfo(key)
	if err != nil {
		return nil, err
	}
	nameCapacity := info.MaxValueNameLen + 1
	if nameCapacity < 512 {
		nameCapacity = 512
	}
	dataCapacity := info.MaxValueLen
	if dataCapacity < 8192 {
		dataCapacity = 8192
	}

	values := []RegistryValue{}
	for index := uint32(0); ; index++ {
		name := make([]uint16, nameCapacity)
		nameLen := uint32(len(name))
		data := make([]byte, dataCapacity)
		dataLen := uint32(len(data))
		var typ uint32
		ret, _, _ := procRegEnumValue.Call(key, uintptr(index), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&dataLen)))
		if ret == errorNoMoreItems {
			break
		}
		if ret != 0 {
			continue
		}
		values = append(values, RegistryValue{
			Name:  syscall.UTF16ToString(name[:nameLen]),
			Type:  typ,
			Value: registryDataString(data[:dataLen], typ),
		})
	}
	return values, nil
}

func Values(parent uintptr, path string) ([]RegistryValue, error) {
	return registryValues(parent, path)
}

func registryDataString(data []byte, typ uint32) string {
	if len(data) == 0 {
		return ""
	}
	if typ == 1 || typ == 2 {
		if len(data)%2 != 0 {
			data = data[:len(data)-1]
		}
		chars := make([]uint16, len(data)/2)
		for i := range chars {
			chars[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
		}
		return wintypes.CleanRegistryString(syscall.UTF16ToString(chars))
	}
	return fmt.Sprintf("%x", data)
}

type keyInfo struct {
	MaxSubKeyLen    uint32
	MaxValueNameLen uint32
	MaxValueLen     uint32
}

func queryKeyInfo(key uintptr) (keyInfo, error) {
	var subKeys uint32
	var maxSubKeyLen uint32
	var values uint32
	var maxValueNameLen uint32
	var maxValueLen uint32
	ret, _, _ := procRegQueryInfoKey.Call(
		key,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&subKeys)),
		uintptr(unsafe.Pointer(&maxSubKeyLen)),
		0,
		uintptr(unsafe.Pointer(&values)),
		uintptr(unsafe.Pointer(&maxValueNameLen)),
		uintptr(unsafe.Pointer(&maxValueLen)),
		0,
		0,
	)
	if ret != 0 {
		return keyInfo{}, syscall.Errno(ret)
	}
	return keyInfo{MaxSubKeyLen: maxSubKeyLen, MaxValueNameLen: maxValueNameLen, MaxValueLen: maxValueLen}, nil
}
