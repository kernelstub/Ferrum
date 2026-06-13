package types

type ServiceInfo struct {
	Name        string
	DisplayName string
	State       string
	StartType   string
	Account     string
	BinaryPath  string
	ProcessID   uint32
	ServiceType uint32
}

type DriverInfo struct {
	Name       string
	State      string
	StartType  string
	BinaryPath string
}

type PipeInfo struct {
	Name string
}

type StartupEntry struct {
	Scope    string
	Location string
	Name     string
	Command  string
}

type ScheduledTask struct {
	Path    string
	Command string
	Author  string
	Enabled string
}

type EnvVar struct {
	Name  string
	Value string
}
