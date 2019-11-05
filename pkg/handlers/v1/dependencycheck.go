package v1

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
)

// DependencyCheckHandler is cool
type DependencyCheckHandler struct {
	DependencyChecker domain.DependencyChecker
}

// Handle calls dependency checker
func (h *DependencyCheckHandler) Handle(ctx context.Context) error {
	return h.DependencyChecker.CheckDependencies(ctx)
}
