//go:build windows

package scheduled

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"

	wintypes "ferrum/windows/types"
)

type ScheduledTask = wintypes.ScheduledTask

type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Settings struct {
		Enabled string `xml:"Enabled"`
	} `xml:"Settings"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func EnumerateScheduledTasks() ([]ScheduledTask, error) {
	root := filepath.Join(os.Getenv("WINDIR"), "System32", "Tasks")
	if os.Getenv("WINDIR") == "" {
		root = `C:\Windows\System32\Tasks`
	}

	tasks := []ScheduledTask{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var parsed taskXML
		if err := xml.Unmarshal(data, &parsed); err != nil {
			return nil
		}
		commands := []string{}
		for _, exec := range parsed.Actions.Exec {
			command := strings.TrimSpace(exec.Command + " " + exec.Arguments)
			if command != "" {
				commands = append(commands, command)
			}
		}
		rel, _ := filepath.Rel(root, path)
		tasks = append(tasks, ScheduledTask{
			Path:    `\` + strings.ReplaceAll(rel, string(filepath.Separator), `\`),
			Command: strings.Join(commands, " | "),
			Author:  parsed.RegistrationInfo.Author,
			Enabled: parsed.Settings.Enabled,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(tasks, func(i, j int) bool { return strings.ToLower(tasks[i].Path) < strings.ToLower(tasks[j].Path) })
	return tasks, nil
}
