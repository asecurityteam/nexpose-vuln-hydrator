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
		assetVulnsResult         []NexposeAssetVulnerability
		assetVulnsError          error
		hydrateVulnsResult       []domain.VulnerabilityDetails
		hydrateVulnsError        error
		expectedAssetVulnDetails domain.AssetVulnerabilityDetails
		expectedErr              bool
	}{
		{
			"success",
			[]NexposeAssetVulnerability{NexposeAssetVulnerability{ID: "vuln1", Status: "vulnerable"}},
			nil,
			[]domain.VulnerabilityDetails{domain.VulnerabilityDetails{ID: "vuln1", Status: "vulnerable"}},
			nil,
			domain.AssetVulnerabilityDetails{
				Asset: domain.Asset{
					ID: assetID,
				},
				Vulnerabilities: []domain.VulnerabilityDetails{domain.VulnerabilityDetails{ID: "vuln1", Status: "vulnerable"}},
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
			[]NexposeAssetVulnerability{NexposeAssetVulnerability{ID: "vuln1"}},
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

func TestHydratorConfigName(t *testing.T) {
	config := HydratorConfig{}
	assert.Equal(t, "hydrator", config.Name())
}

func TestNewHydratorComponent(t *testing.T) {
	c := NewHydratorComponent()
	type DummyConfig func(c *HydratorComponent) *HydratorConfig
	tests := []struct {
		name              string
		hydratorComponent *HydratorComponent
		ctx               context.Context
		config            DummyConfig
		expectedErr       bool
	}{
		{
			name:              "success",
			hydratorComponent: NewHydratorComponent(),
			ctx:               context.Background(),
			config: DummyConfig(func(c *HydratorComponent) *HydratorConfig {
				dummyConfig := c.Settings()
				return dummyConfig
			}),
			expectedErr: false,
		},
		{
			name:              "failure on creating Nexpose Component",
			hydratorComponent: NewHydratorComponent(),
			ctx:               context.Background(),
			config: DummyConfig(func(c *HydratorComponent) *HydratorConfig {
				dummyConfig := c.Settings()
				dummyConfig.Nexpose.Host = "~!@#$%^&*()_+:?><!@#$%^&*())_:/nexpose"
				return dummyConfig
			}),
			expectedErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			_, err := c.New(test.ctx, test.config(test.hydratorComponent))
			assert.Equal(tt, test.expectedErr, err != nil)
		})
	}
}
