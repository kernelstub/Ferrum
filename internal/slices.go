package internal

func Limit[T any](items []T, max int) []T {
	if max <= 0 || len(items) <= max {
		return items
	}
	return items[:max]
}
