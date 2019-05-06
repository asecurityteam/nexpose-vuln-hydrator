package v1

import (
	"context"
	"fmt"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestHandleSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockHydrator := NewMockHydrator(ctrl)
	mockHydrator.EXPECT().HydrateVulnerabilities(gomock.Any()).Return(domain.AssetVulnerabilityDetails{}, nil)

	handler := &HydrationHandler{mockHydrator}
	_, err := handler.Handle(context.Background(), AssetEvent{})

	assert.Nil(t, err)
}

func TestHandleError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockHydrator := NewMockHydrator(ctrl)
	mockHydrator.EXPECT().HydrateVulnerabilities(gomock.Any()).Return(domain.AssetVulnerabilityDetails{}, fmt.Errorf("error"))

	handler := &HydrationHandler{mockHydrator}
	_, err := handler.Handle(context.Background(), AssetEvent{})

	assert.NotNil(t, err)
}

func TestDomainAssetVulnerabilityDetailsToEvent(t *testing.T) {
	domainDetails := domain.AssetVulnerabilityDetails{
		Asset: domain.Asset{
			ID: 111111,
		},
		Vulnerabilities: []domain.VulnerabilityDetails{
			domain.VulnerabilityDetails{
				ID:             "ssl-cert-expired",
				CvssV2Score:    7.0,
				CvssV2Severity: "Medium",
				Description:    "cert expired",
				Title:          "cert expired",
				Solutions:      []string{"update your cert", "alternate"},
				Results: []domain.AssessmentResult{
					domain.AssessmentResult{Port: 443, Protocol: "tcp"},
					domain.AssessmentResult{Port: 80, Protocol: "tcp"},
				},
			},
			domain.VulnerabilityDetails{
				ID:             "additional vuln",
				CvssV2Score:    7.0,
				CvssV2Severity: "Medium",
				Description:    "bad vuln",
				Title:          "vuln",
				Solutions:      []string{"alternate"},
				Results: []domain.AssessmentResult{
					domain.AssessmentResult{Port: 443, Protocol: "tcp"},
				},
			},
		},
	}

	event := domainAssetVulnerabilityDetailsToEvent(domainDetails)

	assert.Len(t, event.AssetVulnerabilityDetails, 2)

	firstEventVuln := event.AssetVulnerabilityDetails[0]
	assert.Len(t, firstEventVuln.Results, 2)

	firstDomainVuln := domainDetails.Vulnerabilities[0]
	assert.Equal(t, firstDomainVuln.ID, firstEventVuln.ID)
	assert.Equal(t, firstDomainVuln.CvssV2Score, firstEventVuln.CvssV2Score)
	assert.Equal(t, firstDomainVuln.CvssV2Severity, firstEventVuln.CvssV2Severity)
	assert.Equal(t, firstDomainVuln.Description, firstEventVuln.Description)
	assert.Equal(t, firstDomainVuln.Title, firstEventVuln.Title)
	assert.Equal(t, firstDomainVuln.Solutions, firstEventVuln.Solutions)
}
