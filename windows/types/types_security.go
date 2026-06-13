package types

type TokenInfo struct {
	User       string
	Integrity  string
	Elevated   bool
	Privileges []string
}

type PolicyFinding struct {
	Name     string
	Value    string
	Severity string
	Reason   string
}
