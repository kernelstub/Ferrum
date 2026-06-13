//go:build !windows

package process

import (
	"runtime"

	winerrors "ferrum/windows/errors"
)

func EnumerateProcesses() ([]Process, error) {
	return nil, winerrors.ErrUnsupported(runtime.GOOS)
}
