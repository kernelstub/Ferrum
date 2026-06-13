package types

import "strings"

func CleanRegistryString(value string) string {
	return strings.TrimRight(value, "\x00")
}
