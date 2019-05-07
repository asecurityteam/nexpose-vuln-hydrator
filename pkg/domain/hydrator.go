package domain

// AssetVulnerabilityDetails is a struct containing the asset information with vulnerabilities
type AssetVulnerabilityDetails struct {
	Asset
	Vulnerabilities []VulnerabilityDetails
}

// VulnerabilityDetails contains the vulnerability information
type VulnerabilityDetails struct {
	ID             string
	Results        []AssessmentResult
	CvssV2Score    float64
	CvssV2Severity string
	Description    string
	Title          string
	Solutions      []string
}

// Hydrator represents an interface for hydrating an Asset with vulnerability details
type Hydrator interface {
	HydrateVulnerabilities(Asset) (AssetVulnerabilityDetails, error)
}
