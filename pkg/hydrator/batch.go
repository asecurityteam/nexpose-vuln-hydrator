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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	solutionsChan := make(chan string, len(solutionIDs))
	errorChan := make(chan error, len(solutionIDs))

	for _, solutionID := range solutionIDs {
		go func(id string) {
			solution, err := b.SolutionFetcher.FetchSolution(ctx, id)
			if err != nil {
				errorChan <- err
				return
			}
			solutionsChan <- solution
		}(solutionID)
	}

	solutions := make([]string, 0, len(solutionIDs))
	for range solutionIDs {
		select {
		case solution := <-solutionsChan:
			solutions = append(solutions, solution)
		case err := <-errorChan:
			cancel()
			return nil, err
		}
	}

	return solutions, nil
}

// BatchCheckFetcher represents an interface for concurrently fetching checks
type BatchCheckFetcher interface {
	BatchFetchCheck(ctx context.Context, checkIDs []string) ([]bool, error)
}

type batchCheckFetcher struct {
	CheckFetcher CheckFetcher
}

func (b *batchCheckFetcher) BatchFetchCheck(ctx context.Context, checkIDs []string) ([]bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	checksChan := make(chan bool, len(checkIDs))
	errorChan := make(chan error, len(checkIDs))

	for _, checkID := range checkIDs {
		go func(id string) {
			check, err := b.CheckFetcher.FetchCheck(ctx, id)
			if err != nil {
				errorChan <- err
				return
			}
			checksChan <- check
		}(checkID)
	}

	checks := make([]bool, 0, len(checkIDs))
	for range checkIDs {
		select {
		case check := <-checksChan:
			checks = append(checks, check)
		case err := <-errorChan:
			cancel()
			return nil, err
		}
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errorChan := make(chan error, 3)

	vulnerabilityDetailsChan := make(chan NexposeVulnerability, 1)
	go func() {
		details, err := a.VulnerabilityDetailsFetcher.FetchVulnerabilityDetails(ctx, assetVulnerability.ID)
		if err != nil {
			errorChan <- err
			return
		}
		vulnerabilityDetailsChan <- details
	}()

	solutionsChan := make(chan []string, 1)
	go func() {
		solutionIDs, err := a.VulnerabilitySolutionsFetcher.FetchVulnerabilitySolutions(ctx, assetVulnerability.ID)
		if err != nil {
			errorChan <- err
			return
		}
		solutions, err := a.BatchSolutionFetcher.BatchFetchSolution(ctx, solutionIDs)
		if err != nil {
			errorChan <- err
			return
		}
		solutionsChan <- solutions
	}()

	checksChan := make(chan []bool, 1)
	go func() {
		checkIDs, err := a.VulnerabilityChecksFetcher.FetchVulnerabilityChecks(ctx, assetVulnerability.ID)
		if err != nil {
			errorChan <- err
			return
		}
		checks, err := a.BatchCheckFetcher.BatchFetchCheck(ctx, checkIDs)
		if err != nil {
			errorChan <- err
			return
		}
		checksChan <- checks
	}()

	vulnerabilityDetails := domain.VulnerabilityDetails{
		ID:      assetVulnerability.ID,
		Results: assetVulnerability.Results,
		Status:  assetVulnerability.Status,
	}

	for i := 0; i < 3; i = i + 1 {
		select {
		case solutions := <-solutionsChan:
			vulnerabilityDetails.Solutions = solutions
		case checks := <-checksChan:
			vulnerabilityDetails.LocalCheck = anyTrue(checks)
		case nexposeVulnDetails := <-vulnerabilityDetailsChan:
			vulnerabilityDetails.CvssV2Score = nexposeVulnDetails.CvssV2Score
			vulnerabilityDetails.CvssV2Severity = nexposeVulnDetails.CvssV2Severity
			vulnerabilityDetails.Description = nexposeVulnDetails.Description
			vulnerabilityDetails.Title = nexposeVulnDetails.Title
		case err := <-errorChan:
			cancel()
			return domain.VulnerabilityDetails{}, err
		}
	}

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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	vulnerabilityDetailsChan := make(chan domain.VulnerabilityDetails, len(assetVulns))
	errorChan := make(chan error, len(assetVulns))

	for _, assetVuln := range assetVulns {
		go func(assetVuln NexposeAssetVulnerability) {
			details, err := b.AssetVulnerabilityHydrator.HydrateAssetVulnerability(ctx, assetVuln)
			if err != nil {
				errorChan <- err
				return
			}
			vulnerabilityDetailsChan <- details
		}(assetVuln)
	}

	vulnerabilityDetails := make([]domain.VulnerabilityDetails, 0, len(assetVulns))
	for range assetVulns {
		select {
		case details := <-vulnerabilityDetailsChan:
			vulnerabilityDetails = append(vulnerabilityDetails, details)
		case err := <-errorChan:
			cancel()
			return nil, err
		}
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
