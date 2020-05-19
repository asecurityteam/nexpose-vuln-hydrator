package hydrator

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
)

// BatchSolutionFetcher represents an interface for concurrently fetching solutions
type BatchSolutionFetcher interface {
	BatchFetchSolution(ctx context.Context, solutionIDs []string) ([]string, error)
}

type batchSolutionFetcher struct {
	SolutionFetcher SolutionFetcher
}

func (b *batchSolutionFetcher) BatchFetchSolution(ctx context.Context, solutionIDs []string) ([]string, error) {
	solutions := make([]string, 0, len(solutionIDs))
	for _, solutionID := range solutionIDs {
		solution, err := b.SolutionFetcher.FetchSolution(ctx, solutionID)
		if err != nil {
			return nil, err
		}
		solutions = append(solutions, solution)
	}
	return solutions, nil
}

// BatchCheckFetcher represents an interface for concurrently fetching checks, and returning
// whether they are local, authenticated checks or not.
type BatchCheckFetcher interface {
	BatchFetchCheck(ctx context.Context, checkIDs []string) ([]bool, error)
}

type batchCheckFetcher struct {
	CheckFetcher CheckFetcher
}

// BatchFetchCheck fetches all the checks represented by checkIDs, and returns whether they
// are local, authenticated checks.
func (b *batchCheckFetcher) BatchFetchCheck(ctx context.Context, checkIDs []string) ([]bool, error) {
	checks := make([]bool, 0, len(checkIDs))
	for _, checkID := range checkIDs {
		check, err := b.CheckFetcher.FetchCheck(ctx, checkID)
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}
	return checks, nil
}

// AssetVulnerabilityHydrator represents an interface for hydrating an asset vulnerability with
// details and solutions
type AssetVulnerabilityHydrator interface {
	HydrateAssetVulnerability(ctx context.Context, assetVulnerability NexposeAssetVulnerability) (domain.VulnerabilityDetails, error)
}

type assetVulnerabilityHydrator struct {
	VulnerabilityDetailsFetcher   VulnerabilityDetailsFetcher
	VulnerabilitySolutionsFetcher VulnerabilitySolutionsFetcher
	VulnerabilityChecksFetcher    VulnerabilityChecksFetcher
	BatchSolutionFetcher          BatchSolutionFetcher
	BatchCheckFetcher             BatchCheckFetcher
}

func (a *assetVulnerabilityHydrator) HydrateAssetVulnerability(ctx context.Context, assetVulnerability NexposeAssetVulnerability) (domain.VulnerabilityDetails, error) {
	vulnDetails, err := a.VulnerabilityDetailsFetcher.FetchVulnerabilityDetails(ctx, assetVulnerability.ID)
	if err != nil {
		return domain.VulnerabilityDetails{}, err
	}
	vulnerabilityDetails := domain.VulnerabilityDetails{
		ID:             assetVulnerability.ID,
		Results:        assetVulnerability.Results,
		Status:         assetVulnerability.Status,
		CvssV2Score:    vulnDetails.CvssV2Score,
		CvssV2Severity: vulnDetails.CvssV2Severity,
		Description:    vulnDetails.Description,
		Title:          vulnDetails.Title,
	}

	solutionIDs, err := a.VulnerabilitySolutionsFetcher.FetchVulnerabilitySolutions(ctx, assetVulnerability.ID)
	if err != nil {
		return domain.VulnerabilityDetails{}, err
	}
	solutions, err := a.BatchSolutionFetcher.BatchFetchSolution(ctx, solutionIDs)
	if err != nil {
		return domain.VulnerabilityDetails{}, err
	}
	vulnerabilityDetails.Solutions = solutions

	checkIDs, err := a.VulnerabilityChecksFetcher.FetchVulnerabilityChecks(ctx, assetVulnerability.ID)
	if err != nil {
		return domain.VulnerabilityDetails{}, err
	}
	checks, err := a.BatchCheckFetcher.BatchFetchCheck(ctx, checkIDs)
	if err != nil {
		return domain.VulnerabilityDetails{}, err
	}
	vulnerabilityDetails.LocalCheck = anyTrue(checks)
	return vulnerabilityDetails, nil
}

// BatchAssetVulnerabilityHydrator represents an interface for concurrently hydrating asset vulnerabilities
type BatchAssetVulnerabilityHydrator interface {
	BatchHydrateAssetVulnerabilities(ctx context.Context, assetVulns []NexposeAssetVulnerability) ([]domain.VulnerabilityDetails, error)
}

type batchAssetVulnerabilityHydrator struct {
	AssetVulnerabilityHydrator AssetVulnerabilityHydrator
}

func (b *batchAssetVulnerabilityHydrator) BatchHydrateAssetVulnerabilities(ctx context.Context, assetVulns []NexposeAssetVulnerability) ([]domain.VulnerabilityDetails, error) {
	vulnerabilityDetails := make([]domain.VulnerabilityDetails, 0, len(assetVulns))
	for _, assetVuln := range assetVulns {
		details, err := b.AssetVulnerabilityHydrator.HydrateAssetVulnerability(ctx, assetVuln)
		if err != nil {
			return nil, err
		}
		vulnerabilityDetails = append(vulnerabilityDetails, details)
	}
	return vulnerabilityDetails, nil
}

func anyTrue(checks []bool) bool {
	for _, check := range checks {
		if check == true {
			return true
		}
	}
	return false
}
