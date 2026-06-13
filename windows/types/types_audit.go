package types

type DLLSearchPathFinding struct {
	Path     string
	Source   string
	Severity string
	Reason   string
}

type AdvancedFinding struct {
	Area     string
	Target   string
	Name     string
	Value    string
	Severity string
	Reason   string
}
