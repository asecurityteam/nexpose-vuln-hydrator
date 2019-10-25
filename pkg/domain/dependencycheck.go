package domain

import "context"

// Hydrator represents an interface for hydrating an Asset with vulnerability details
type DependencyChecker interface {
	DepCheck(context.Context) error
}
