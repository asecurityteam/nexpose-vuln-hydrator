package hydrator

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
)

// VulnerabilitySolutionsFetcher represents an interface for fetching vulnerability solutions
type VulnerabilitySolutionsFetcher interface {
	FetchVulnerabilitySolutions(ctx context.Context, vulnID string) ([]string, error)
}

// SolutionFetcher represents an interface for fetching solution remediation
type SolutionFetcher interface {
	FetchSolution(ctx context.Context, solutionID string) (string, error)
}

// AssetVulnerabilitiesFetcher represents an interface for fetching asset vulnerabilities
type AssetVulnerabilitiesFetcher interface {
	FetchAssetVulnerabilities(ctx context.Context, assetID int64) ([]domain.NexposeAssetVulnerability, error)
}

// VulnerabilityDetailsFetcher represents an interface for fetching vulnerability details
type VulnerabilityDetailsFetcher interface {
	FetchVulnerabilityDetails(ctx context.Context, vulnID string) (domain.NexposeVulnerability, error)
}
