package domain

import "context"

// DependencyChecker represents an interface for checking whether
// this app's dependencies are reachable
type DependencyChecker interface {
	CheckDependencies(context.Context) error
}
