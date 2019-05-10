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
