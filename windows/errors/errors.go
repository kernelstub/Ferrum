package errors

import "fmt"

type ErrUnsupported string

func (e ErrUnsupported) Error() string {
	return fmt.Sprintf("Windows API enumeration is not supported on %s", string(e))
}
