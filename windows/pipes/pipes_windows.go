//go:build windows

package pipes

import (
	"os"
	"sort"
	"strings"

	wintypes "ferrum/windows/types"
)

type PipeInfo = wintypes.PipeInfo

func EnumerateNamedPipes() ([]PipeInfo, error) {
	entries, err := os.ReadDir(`\\.\pipe\`)
	if err != nil {
		return nil, err
	}
	pipes := make([]PipeInfo, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.TrimSpace(name) == "" {
			continue
		}
		pipes = append(pipes, PipeInfo{Name: name})
	}
	sort.Slice(pipes, func(i, j int) bool { return strings.ToLower(pipes[i].Name) < strings.ToLower(pipes[j].Name) })
	return pipes, nil
}
