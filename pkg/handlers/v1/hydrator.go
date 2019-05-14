package v1

import (
	"context"
	"time"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/logs"
)

// HydrationHandler consumes AssetEvents, hydrates them with vulnerability details,
// and returns an AssetVulnerabilitiesEvent or error
type HydrationHandler struct {
	Hydrator domain.Hydrator
	LogFn    domain.LogFn
}

// AssetEvent contains JSON annotations for scanned Asset events
type AssetEvent struct {
	LastScanned time.Time `json:"lastScanned"`
	ID          int64     `json:"id"`
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
}

// AssetVulnerabilitiesEvent contains the Asset event hydrated with vulnerability details
type AssetVulnerabilitiesEvent struct {
	AssetEvent
	AssetVulnerabilityDetails []AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// AssetVulnerabilityDetails contains pertinent information about a vulnerability
type AssetVulnerabilityDetails struct {
	ID             string             `json:"id"`
	Results        []AssessmentResult `json:"results"`
	CvssV2Score    float64            `json:"cvssV2Score"`
	CvssV2Severity string             `json:"cvssV2Severity"`
	Description    string             `json:"description"`
	Title          string             `json:"title"`
	Solutions      []string           `json:"solutions"`
}

// AssessmentResult contains information about the port/protocol the vulnerability was discovered on
type AssessmentResult struct {
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

// Handle accepts AssetEvents and returns a hydrated asset containing vulnerability information
func (h *HydrationHandler) Handle(ctx context.Context, evt AssetEvent) (AssetVulnerabilitiesEvent, error) {
	logger := h.LogFn(ctx)
	asset := domain.Asset(evt)
	assetWithVulnerabilityDetails, err := h.Hydrator.HydrateVulnerabilities(ctx, asset)
	if err != nil {
		logger.Error(logs.HydrationError{Reason: err.Error()})
		return AssetVulnerabilitiesEvent{}, err
	}
	return domainAssetVulnerabilityDetailsToEvent(assetWithVulnerabilityDetails), nil
}

func domainAssetVulnerabilityDetailsToEvent(a domain.AssetVulnerabilityDetails) AssetVulnerabilitiesEvent {
	vulnerabilityDetails := make([]AssetVulnerabilityDetails, len(a.Vulnerabilities))
	for i, vuln := range a.Vulnerabilities {
		results := make([]AssessmentResult, len(vuln.Results))
		for j, result := range vuln.Results {
			results[j] = AssessmentResult(result)
		}
		vulnerabilityDetails[i] = AssetVulnerabilityDetails{
			ID:             vuln.ID,
			Results:        results,
			CvssV2Score:    vuln.CvssV2Score,
			CvssV2Severity: vuln.CvssV2Severity,
			Description:    vuln.Description,
			Title:          vuln.Title,
			Solutions:      vuln.Solutions,
		}
	}
	return AssetVulnerabilitiesEvent{
		AssetEvent:                AssetEvent(a.Asset),
		AssetVulnerabilityDetails: vulnerabilityDetails,
	}
}