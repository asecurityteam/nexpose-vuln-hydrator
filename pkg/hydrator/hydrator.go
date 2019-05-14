package hydrator

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
)

// Hydrator implements the domain.Hydrator interface
type Hydrator struct {
	AssetVulnerabilitiesFetcher     AssetVulnerabilitiesFetcher
	BatchAssetVulnerabilityHydrator BatchAssetVulnerabilityHydrator
}

// HydrateVulnerabilities accepts a domain.Asset and fetches the information necessary to populate its vulnerabilities
func (h *Hydrator) HydrateVulnerabilities(ctx context.Context, a domain.Asset) (domain.AssetVulnerabilityDetails, error) {
	assetVulnerabilities, err := h.AssetVulnerabilitiesFetcher.FetchAssetVulnerabilities(ctx, a.ID)
	if err != nil {
		return domain.AssetVulnerabilityDetails{}, err
	}

	hydratedVulnerabilities, err := h.BatchAssetVulnerabilityHydrator.BatchHydrateAssetVulnerabilities(ctx, assetVulnerabilities)
	if err != nil {
		return domain.AssetVulnerabilityDetails{}, err
	}

	return domain.AssetVulnerabilityDetails{
		Asset:           a,
		Vulnerabilities: hydratedVulnerabilities,
	}, nil
}
