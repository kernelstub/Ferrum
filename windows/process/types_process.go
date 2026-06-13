package process

type Process struct {
	PID        uint32
	ParentPID  uint32
	Name       string
	Exe        string
	User       string
	Integrity  string
	Elevated   bool
	Privileges []string
}

func (p Process) Label() string {
	user := p.User
	if user == "" {
		user = "Token"
	}
	if p.Integrity != "" {
		return user + " / " + p.Integrity
	}
	return user
}

type ProcessMitigation struct {
	Process
	DEP    string
	ASLR   string
	Strict string
	CFG    string
}
