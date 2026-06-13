package output

import (
	"fmt"
	"io"
	"sync"
)

type ConsoleLogger struct {
	out      io.Writer
	artifact io.Writer
	verbose  bool
	quiet    bool
	mu       sync.Mutex
}

func NewConsoleLogger(out io.Writer, verbose, quiet bool) *ConsoleLogger {
	return &ConsoleLogger{out: out, verbose: verbose, quiet: quiet}
}

func NewDualLogger(out, artifact io.Writer, verbose, quiet bool) *ConsoleLogger {
	return &ConsoleLogger{out: out, artifact: artifact, verbose: verbose, quiet: quiet}
}

func (l *ConsoleLogger) Info(message string) {
	l.printf(!l.quiet, "[*] %s\n", message)
}

func (l *ConsoleLogger) Success(message string) {
	l.printf(!l.quiet, "[+] %s\n", message)
}

func (l *ConsoleLogger) Error(message string) {
	l.printf(true, "[-] %s\n", message)
}

func (l *ConsoleLogger) Verbose(message string) {
	if !l.verbose {
		return
	}
	l.printf(!l.quiet, "[v] %s\n", message)
}

func (l *ConsoleLogger) printf(writeConsole bool, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if writeConsole {
		fmt.Fprintf(l.out, format, args...)
	}
	if l.artifact != nil {
		fmt.Fprintf(l.artifact, format, args...)
	}
}
