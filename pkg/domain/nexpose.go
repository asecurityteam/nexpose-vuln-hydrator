package domain

// NexposeAssetVulnerability contains the vulnerability ID and assessment
// results from the getAssetVulnerabilities Nexpose response payload
type NexposeAssetVulnerability struct {
	ID      string
	Results []AssessmentResult
}

// AssessmentResult contains port and protcol information from Nexpose scanning
type AssessmentResult struct {
	Port     int32
	Protocol string
}

// NexposeVulnerability contains the vulnerability details from the
// Nexpose getVulnerability Nexpose response payload
type NexposeVulnerability struct {
	CvssV2Score    float64
	CvssV2Severity string
	Description    string
	Title          string
}

// NexposeClient represents an interface used to interact with the Nexpose API
type NexposeClient interface {
	GetAssetVulnerabilities(int64) ([]NexposeAssetVulnerability, error)
	GetVulnerabilityDetails(string) (NexposeVulnerability, error)
	GetVulnerabilitySolutions(string) ([]string, error)
	GetVulnerabilitySolutionDetails(string) ([]string, error)
}
