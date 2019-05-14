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

// AssetVulnerabilityHydrator represents an interface for hydrating an asset vulnerability with
// details and solutions
type AssetVulnerabilityHydrator interface {
	HydrateAssetVulnerability(ctx context.Context, assetVulnerability nexposeAssetVulnerability) (domain.VulnerabilityDetails, error)
}

type assetVulnerabilityHydrator struct {
	VulnerabilityDetailsFetcher   VulnerabilityDetailsFetcher
	VulnerabilitySolutionsFetcher VulnerabilitySolutionsFetcher
	BatchSolutionFetcher          BatchSolutionFetcher
}

func (a *assetVulnerabilityHydrator) HydrateAssetVulnerability(ctx context.Context, assetVulnerability nexposeAssetVulnerability) (domain.VulnerabilityDetails, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errorChan := make(chan error, 2)

	vulnerabilityDetailsChan := make(chan nexposeVulnerability, 1)
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

	vulnerabilityDetails := domain.VulnerabilityDetails{
		ID:      assetVulnerability.ID,
		Results: assetVulnerability.Results,
	}

	for i := 0; i < 2; i = i + 1 {
		select {
		case solutions := <-solutionsChan:
			vulnerabilityDetails.Solutions = solutions
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
	BatchHydrateAssetVulnerabilities(ctx context.Context, assetVulns []nexposeAssetVulnerability) ([]domain.VulnerabilityDetails, error)
}

type batchAssetVulnerabilityHydrator struct {
	AssetVulnerabilityHydrator AssetVulnerabilityHydrator
}

func (b *batchAssetVulnerabilityHydrator) BatchHydrateAssetVulnerabilities(ctx context.Context, assetVulns []nexposeAssetVulnerability) ([]domain.VulnerabilityDetails, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	vulnerabilityDetailsChan := make(chan domain.VulnerabilityDetails, len(assetVulns))
	errorChan := make(chan error, len(assetVulns))

	for _, assetVuln := range assetVulns {
		go func(assetVuln nexposeAssetVulnerability) {
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
