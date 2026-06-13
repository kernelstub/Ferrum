package core

type Logger interface {
	Info(message string)
	Success(message string)
	Error(message string)
	Verbose(message string)
}

type Context struct {
	Logger Logger
	Build  string
}

func NewContext(logger Logger, build string) *Context {
	return &Context{Logger: logger, Build: build}
}
