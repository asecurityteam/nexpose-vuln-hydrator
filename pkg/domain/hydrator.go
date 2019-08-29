package domain

import "context"

// AssetVulnerabilityDetails is a struct containing the asset information with vulnerabilities
type AssetVulnerabilityDetails struct {
	Asset
	Vulnerabilities []VulnerabilityDetails
}

// AssessmentResult contains port and protcol information from Nexpose scanning
type AssessmentResult struct {
	Port     int32
	Protocol string
}

// VulnerabilityDetails contains the vulnerability information
type VulnerabilityDetails struct {
	ID             string
	Results        []AssessmentResult
	Status         string
	CvssV2Score    float64
	CvssV2Severity string
	Description    string
	Title          string
	Solutions      []string
}

// Hydrator represents an interface for hydrating an Asset with vulnerability details
type Hydrator interface {
	HydrateVulnerabilities(context.Context, Asset) (AssetVulnerabilityDetails, error)
}
