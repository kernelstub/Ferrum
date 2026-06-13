package core

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Module interface {
	Name() string
	Description() string
	Run(ctx *Context) error
}

var (
	mu       sync.RWMutex
	registry = make(map[string]Module)
)

func Register(module Module) {
	name := strings.ToLower(strings.TrimSpace(module.Name()))
	if name == "" {
		panic("module name cannot be empty")
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("module already registered: %s", name))
	}
	registry[name] = module
}

func Modules() []Module {
	mu.RLock()
	defer mu.RUnlock()

	modules := make([]Module, 0, len(registry))
	for _, module := range registry {
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Name() < modules[j].Name()
	})
	return modules
}
