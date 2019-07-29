package hydrator

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
)

// HydratorConfig contains items to be configured for the HydratorComponent.
type HydratorConfig struct {
	Nexpose *NexposeConfig
}

// Name is used by the settings library and will add a "HYDRATOR_"
// prefix to all app environment variables
func (*HydratorConfig) Name() string {
	return "hydrator"
}

// HydratorComponent contains other components that need to be configured.
type HydratorComponent struct {
	Nexpose *NexposeComponent
}

// NewHydratorComponent generates and returns a HydratorComponent
func NewHydratorComponent() *HydratorComponent {
	return &HydratorComponent{
		Nexpose: NewNexposeComponent(),
	}
}

// Settings can be used to populate default values if there are any
func (c *HydratorComponent) Settings() *HydratorConfig {
	return &HydratorConfig{
		Nexpose: c.Nexpose.Settings(),
	}
}

// New configures and returns a new Hydrator with all default configs set
func (c *HydratorComponent) New(ctx context.Context, config *HydratorConfig) (*Hydrator, error) {
	nexposeClient, e := c.Nexpose.New(ctx, config.Nexpose)
	if e != nil {
		return nil, e
	}
	hydrator := &Hydrator{
		AssetVulnerabilitiesFetcher: nexposeClient,
		BatchAssetVulnerabilityHydrator: &batchAssetVulnerabilityHydrator{
			AssetVulnerabilityHydrator: &assetVulnerabilityHydrator{
				VulnerabilityDetailsFetcher:   nexposeClient,
				VulnerabilitySolutionsFetcher: nexposeClient,
				BatchSolutionFetcher: &batchSolutionFetcher{
					SolutionFetcher: nexposeClient,
				},
			},
		},
	}
	return hydrator, nil
}

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
