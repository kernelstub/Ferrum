//go:build windows

package registry

import (
	"fmt"
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
	procRegQueryValueEx = advapi32.NewProc("RegQueryValueExW")
)

type RegistryValue struct {
	Name  string
	Type  uint32
	Value string
}

func EnumerateHKCUCLSID() ([]CLSIDEntry, error) {
	root, err := openKey(hkeyCurrentUser, `Software\Classes\CLSID`)
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
		for _, kind := range []string{"InprocServer32", "LocalServer32", "TreatAs", "ProgID"} {
			subkey, err := openKey(root, clsid+`\`+kind)
			if err != nil {
				continue
			}
			value, _ := queryDefaultValue(subkey)
			procRegCloseKey.Call(subkey)
			entries = append(entries, CLSIDEntry{CLSID: clsid, Kind: kind, Value: value})
		}
	}
	return entries, nil
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
	keys := []string{}
	for index := uint32(0); ; index++ {
		name := make([]uint16, 256)
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

	values := []RegistryValue{}
	for index := uint32(0); ; index++ {
		name := make([]uint16, 512)
		nameLen := uint32(len(name))
		data := make([]byte, 8192)
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
