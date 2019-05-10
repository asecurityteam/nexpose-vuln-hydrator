package hydrator

import (
	"context"
	"fmt"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestHydrator(t *testing.T) {
	var assetID int64 = 111111
	tests := []struct {
		name                     string
		assetVulnsResult         []domain.NexposeAssetVulnerability
		assetVulnsError          error
		hydrateVulnsResult       []domain.VulnerabilityDetails
		hydrateVulnsError        error
		expectedAssetVulnDetails domain.AssetVulnerabilityDetails
		expectedErr              bool
	}{
		{
			"success",
			[]domain.NexposeAssetVulnerability{domain.NexposeAssetVulnerability{ID: "vuln1"}},
			nil,
			[]domain.VulnerabilityDetails{domain.VulnerabilityDetails{ID: "vuln1"}},
			nil,
			domain.AssetVulnerabilityDetails{
				Asset: domain.Asset{
					ID: assetID,
				},
				Vulnerabilities: []domain.VulnerabilityDetails{domain.VulnerabilityDetails{ID: "vuln1"}},
			},
			false,
		},
		{
			"fetch asset vulns error",
			nil,
			fmt.Errorf("fetch asset vulns error"),
			[]domain.VulnerabilityDetails{domain.VulnerabilityDetails{ID: "vuln1"}},
			nil,
			domain.AssetVulnerabilityDetails{},
			true,
		},
		{
			"hydrate asset vulns error",
			[]domain.NexposeAssetVulnerability{domain.NexposeAssetVulnerability{ID: "vuln1"}},
			nil,
			nil,
			fmt.Errorf("fetch asset vulns error"),
			domain.AssetVulnerabilityDetails{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			mockAssetVulnsFetcher := NewMockAssetVulnerabilitiesFetcher(ctrl)
			mockAssetVulnsFetcher.EXPECT().FetchAssetVulnerabilities(gomock.Any(), gomock.Any()).Return(test.assetVulnsResult, test.assetVulnsError)
			mockAssetVulnHydrator := NewMockBatchAssetVulnerabilityHydrator(ctrl)
			mockAssetVulnHydrator.EXPECT().BatchHydrateAssetVulnerabilities(gomock.Any(), gomock.Any()).Return(test.hydrateVulnsResult, test.hydrateVulnsError)

			hydrator := Hydrator{mockAssetVulnsFetcher, mockAssetVulnHydrator}
			details, err := hydrator.HydrateVulnerabilities(context.Background(), domain.Asset{ID: assetID})
			if test.expectedErr {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.Equal(tt, test.expectedAssetVulnDetails, details)
			}
		})
	}
}
