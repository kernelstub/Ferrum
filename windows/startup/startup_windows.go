//go:build windows

package startup

import (
	"os"
	"path/filepath"
	"sort"

	"ferrum/windows/registry"
	wintypes "ferrum/windows/types"
)

type StartupEntry = wintypes.StartupEntry

func EnumerateStartupEntries() ([]StartupEntry, error) {
	entries := []StartupEntry{}
	registryLocations := []struct {
		scope uintptr
		name  string
		path  string
	}{
		{registry.HkeyCurrentUser, "User", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.HkeyCurrentUser, "User", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.HkeyLocalMachine, "Machine", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.HkeyLocalMachine, "Machine", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.HkeyLocalMachine, "Machine32", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	}

	for _, location := range registryLocations {
		values, err := registry.Values(location.scope, location.path)
		if err != nil {
			continue
		}
		for _, value := range values {
			entries = append(entries, StartupEntry{
				Scope:    location.name,
				Location: location.path,
				Name:     value.Name,
				Command:  value.Value,
			})
		}
	}

	startupFolders := []struct {
		scope string
		path  string
	}{
		{"User", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
		{"Machine", filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
	}
	for _, folder := range startupFolders {
		if folder.path == "" {
			continue
		}
		files, err := os.ReadDir(folder.path)
		if err != nil {
			continue
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			entries = append(entries, StartupEntry{
				Scope:    folder.scope,
				Location: folder.path,
				Name:     file.Name(),
				Command:  filepath.Join(folder.path, file.Name()),
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Scope != entries[j].Scope {
			return entries[i].Scope < entries[j].Scope
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}
