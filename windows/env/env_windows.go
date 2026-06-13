//go:build windows

package env

import (
	"os"
	"sort"
	"strings"

	wintypes "ferrum/windows/types"
)

type EnvVar = wintypes.EnvVar

func EnumerateEnvironment() ([]EnvVar, error) {
	raw := os.Environ()
	vars := make([]EnvVar, 0, len(raw))
	for _, item := range raw {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		vars = append(vars, EnvVar{Name: name, Value: value})
	}
	sort.Slice(vars, func(i, j int) bool { return strings.ToUpper(vars[i].Name) < strings.ToUpper(vars[j].Name) })
	return vars, nil
}
