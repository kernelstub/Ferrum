package registry

type CLSIDEntry struct {
	CLSID string
	Kind  string
	Value string
}

type CLSIDProcMonCandidate struct {
	CLSID        string
	Kind         string
	Path         string
	Result       string
	MachineValue string
}

type RegistryAuditFinding struct {
	Scope    string
	Path     string
	Name     string
	Value    string
	Severity string
	Reason   string
}
