package hydrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
)

const (
	pageQueryParam = "page" // The index of the page (zero-based) to retrieve.
	sizeQueryParam = "size" // The number of records per page to retrieve.
)

// NexposeAssetVulnerability represents the relevant fields from a Nexpose Assset Vulnerability
type NexposeAssetVulnerability struct {
	ID      string
	Results []domain.AssessmentResult
	Status  string
}

// NexposeVulnerability represents the relevant fields from a Nexpose Vulnerability
type NexposeVulnerability struct {
	CvssV2Score    float64
	CvssV2Severity string
	Description    string
	Status         string
	Title          string
}

type vulnerabilitySolutions struct {
	Links     []link   `json:"links"`
	Resources []string `json:"resources"`
}

type link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

// VulnerabilitySolutionsFetcher represents an interface for fetching vulnerability solutions
type VulnerabilitySolutionsFetcher interface {
	FetchVulnerabilitySolutions(ctx context.Context, vulnID string) ([]string, error)
}

type solution struct {
	AdditionalInformation htmlAndTextObject `json:"additionalInformation"`
	AppliesTo             string            `json:"appliesTo"`
	Estimate              string            `json:"estimate"`
	ID                    string            `json:"id"`
	Steps                 htmlAndTextObject `json:"steps"`
	Summary               htmlAndTextObject `json:"summary"`
	Type                  string            `json:"type"`
}

type htmlAndTextObject struct {
	HTML string `json:"html"`
	Text string `json:"text"`
}

// SolutionFetcher represents an interface for fetching solution remediation
type SolutionFetcher interface {
	FetchSolution(ctx context.Context, solutionID string) (string, error)
}

type assetVulnerabilities struct {
	Links     []link     `json:"links"`
	Page      page       `json:"page"`
	Resources []resource `json:"resources"`
}

type page struct {
	Number         int64 `json:"number"`
	Size           int64 `json:"size"`
	TotalPages     int64 `json:"totalPages"`
	TotalResources int64 `json:"totalResources"`
}

type resource struct {
	ID        string   `json:"id"`
	Instances int      `json:"instances"`
	Links     []link   `json:"links"`
	Results   []result `json:"results"`
	Status    string   `json:"status"`
}

type result struct {
	CheckID    string  `json:"checkId"`
	Exceptions []int32 `json:"exceptions"`
	Key        string  `json:"key"`
	Links      []link  `json:"links"`
	Port       int32   `json:"port"`
	Proof      string  `json:"proof"`
	Protocol   string  `json:"protocol"`
	Status     string  `json:"status"`
}

// AssetVulnerabilitiesFetcher represents an interface for fetching asset vulnerabilities
type AssetVulnerabilitiesFetcher interface {
	FetchAssetVulnerabilities(ctx context.Context, assetID int64) ([]NexposeAssetVulnerability, error)
}

type vulnerabilityDetails struct {
	Added           string            `json:"added"`
	Categories      []string          `json:"categories"`
	CVEs            []string          `json:"cves"`
	CVSS            cvss              `json:"cvss"`
	DenialOfService bool              `json:"denialOfService"`
	Description     htmlAndTextObject `json:"description"`
	Exploits        int32             `json:"exploits"`
	ID              string            `json:"id"`
	Links           []link            `json:"links"`
	MalewareKits    int32             `json:"malewareKits"`
	Modified        string            `json:"modified"`
	Pci             json.RawMessage   `json:"pci"`
	Published       string            `json:"published"`
	RiskScore       float32           `json:"riskScore"`
	Severity        string            `json:"severity"`
	Title           string            `json:"title"`
}

type cvss struct {
	Links []link `json:"links"`
	V2    cvssV2 `json:"v2"`
	V3    cvssV3 `json:"v3"`
}

type cvssV2 struct {
	AccessComplexity      string  `json:"accessComplexity"`
	AccessVector          string  `json:"acessVector"`
	Authentication        string  `json:"authentication"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	ExploitScore          float32 `json:"exploitScore"`
	ImpactScore           float32 `json:"impactScore"`
	IntegrityImpact       string  `json:"integrityImpact"`
	Score                 float64 `json:"score"`
	Vector                string  `json:"vector"`
}

type cvssV3 struct {
	AttackComplexity      string  `json:"attackComplexity"`
	AttackVector          string  `json:"attackVector"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	ExploitScore          float32 `json:"exploitScore"`
	ImpactScore           float32 `json:"impactScore"`
	IntegrityImpact       string  `json:"integrityImpact"`
	PrivilegeRequired     string  `json:"privilegeRequired"`
	Scope                 string  `json:"scope"`
	Score                 float32 `json:"score"`
	UserInteraction       string  `json:"userInteraction"`
	Vector                string  `json:"vector"`
}

// VulnerabilityDetailsFetcher represents an interface for fetching vulnerability details
type VulnerabilityDetailsFetcher interface {
	FetchVulnerabilityDetails(ctx context.Context, vulnID string) (NexposeVulnerability, error)
}

// NexposeClient implements the interfaces to fetch vulnerabilities and solutions from nexpose
type NexposeClient struct {
	HTTPClient *http.Client
	Host       *url.URL
	PageSize   int
}

// PermanentError is used as a signal for callers of makeNexposeRequest
// to handle permanent errors from Nexpose
type PermanentError struct {
}

func (pe *PermanentError) Error() string {
	return "Permanent Nexpose Error"
}

// FetchVulnerabilitySolutions fetches the solutions to a particular vulnerability
func (n *NexposeClient) FetchVulnerabilitySolutions(ctx context.Context, vulnID string) ([]string, error) {
	body, err := n.makeNexposeRequest(nil, "api", "3", "vulnerabilities", vulnID, "solutions") // handle permanent errors
	var solutions vulnerabilitySolutions
	if err != nil {
		switch err.(type) {
		case *PermanentError:
			return solutions.Resources, nil
		default:
			return nil, err
		}
	}
	err = json.Unmarshal(body, &solutions)
	if err != nil {
		return nil, err
	}
	return solutions.Resources, nil
}

// FetchSolution fetches details about a particular solution
func (n *NexposeClient) FetchSolution(ctx context.Context, solutionID string) (string, error) {
	body, err := n.makeNexposeRequest(nil, "api", "3", "solutions", solutionID) //handle permanent failures
	if err != nil {
		switch err.(type) {
		case *PermanentError:
			return "Could not get solution from Nexpose", nil // is this ok? like the message?
		default:
			return "", err
		}
	}
	var solutionDetails solution
	err = json.Unmarshal(body, &solutionDetails)
	if err != nil {
		return "", err
	}
	return solutionDetails.Steps.Text, nil
}

// FetchVulnerabilityDetails fetches details about a particular vulnerability
func (n *NexposeClient) FetchVulnerabilityDetails(ctx context.Context, vulnID string) (NexposeVulnerability, error) {
	body, err := n.makeNexposeRequest(nil, "api", "3", "vulnerabilities", vulnID) //handle permanent errors!
	if err != nil {
		switch err.(type) {
		case *PermanentError:
			return NexposeVulnerability{
				Title:          "Can't get Nexpose Title",
				Description:    "Can't get Nexpose Description",
				CvssV2Score:    0,
				CvssV2Severity: "unknown",
			}, nil // What do we want to fill in with this struct?
		default:
			return NexposeVulnerability{}, err
		}
	}
	var vulnDetails vulnerabilityDetails
	err = json.Unmarshal(body, &vulnDetails)
	if err != nil {
		return NexposeVulnerability{}, err
	}
	return NexposeVulnerability{
		Title:          vulnDetails.Title,
		Description:    vulnDetails.Description.Text,
		CvssV2Score:    vulnDetails.CVSS.V2.Score,
		CvssV2Severity: cvssV2Severity(vulnDetails.CVSS.V2.Score),
	}, nil
}

// FetchAssetVulnerabilities fetches the list of vulnerabilities for an asset
func (n *NexposeClient) FetchAssetVulnerabilities(ctx context.Context, assetID int64) ([]NexposeAssetVulnerability, error) {
	body, err := n.makeNexposeRequest( // no need to check for permanent errors..
		map[string]string{pageQueryParam: "0", sizeQueryParam: strconv.Itoa(n.PageSize)},
		"api", "3", "assets", strconv.FormatInt(assetID, 10), "vulnerabilities",
	)
	if err != nil {
		return nil, err
	}
	var assetVulns assetVulnerabilities
	err = json.Unmarshal(body, &assetVulns)
	if err != nil {
		return nil, err
	}

	pages := int(assetVulns.Page.TotalPages)
	totalResources := int(assetVulns.Page.TotalResources)
	assetVulnsChannel := make(chan NexposeAssetVulnerability, totalResources)
	errorChan := make(chan error, pages)
	for _, resource := range assetVulns.Resources {
		assetVulnsChannel <- assetVulnToNexposeAssetVuln(resource)
	}

	for curPage := 1; curPage < pages; curPage = curPage + 1 {
		go func(curPage int) {
			nexposeAssetVulns, err := n.makePagedAssetVulnerabilitiesRequest(assetID, curPage)
			if err != nil {
				errorChan <- err
				return
			}
			for _, vuln := range nexposeAssetVulns {
				assetVulnsChannel <- vuln
			}
		}(curPage)
	}

	nexposeAssetVulns := make([]NexposeAssetVulnerability, 0, totalResources)
	for i := 0; i < totalResources; i = i + 1 {
		select {
		case assetVuln := <-assetVulnsChannel:
			nexposeAssetVulns = append(nexposeAssetVulns, assetVuln)
		case err := <-errorChan:
			return nil, err
		}
	}
	return nexposeAssetVulns, nil
}

func (n *NexposeClient) makePagedAssetVulnerabilitiesRequest(assetID int64, page int) ([]NexposeAssetVulnerability, error) {
	body, err := n.makeNexposeRequest(
		map[string]string{pageQueryParam: strconv.Itoa(page), sizeQueryParam: strconv.Itoa(n.PageSize)},
		"api", "3", "assets", strconv.FormatInt(assetID, 10), "vulnerabilities", // no need to handle permanent errors
	)
	if err != nil {
		return nil, err
	}
	var assetVulns assetVulnerabilities
	err = json.Unmarshal(body, &assetVulns)
	if err != nil {
		return nil, err
	}

	nexposeAssetVulns := make([]NexposeAssetVulnerability, 0, len(assetVulns.Resources))
	for _, resource := range assetVulns.Resources {
		nexposeAssetVulns = append(nexposeAssetVulns, assetVulnToNexposeAssetVuln(resource))
	}
	return nexposeAssetVulns, nil
}

func (n *NexposeClient) makeNexposeRequest(queryParams map[string]string, pathFragments ...string) ([]byte, error) {
	u, _ := url.Parse(n.Host.String())
	u.Path = path.Join(pathFragments...)
	q := u.Query()
	for k, v := range queryParams {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	res, err := n.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		// this implies permanent error, to which results in an error we should act on
		// based on the caller
		if res.StatusCode >= 400 && res.StatusCode <= 500 {
			return nil, &PermanentError{}
		}
		// Nexpose is down?  Nexpose unexpectedly gave 404?
		headers, errMarshal := json.Marshal(res.Header)
		if errMarshal != nil {
			headers = []byte("(could not marshal response headers)")
		}
		return nil, fmt.Errorf("Nexpose unexpectedly returned non-200 response code: %d attempting to GET: %s.  Response headers: %s", res.StatusCode, u.String(), string(headers))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func assetVulnToNexposeAssetVuln(resource resource) NexposeAssetVulnerability {
	results := make([]domain.AssessmentResult, 0, len(resource.Results))
	for _, result := range resource.Results {
		results = append(results, domain.AssessmentResult{
			Port:     result.Port,
			Protocol: result.Protocol,
			Proof:    result.Proof,
		})
	}
	return NexposeAssetVulnerability{
		ID:      resource.ID,
		Results: results,
		Status:  resource.Status,
	}
}

func cvssV2Severity(score float64) string {
	if score >= 0.0 && score <= 3.9 {
		return "Low"
	} else if score >= 4.0 && score <= 6.9 {
		return "Medium"
	} else if score >= 7.0 && score <= 10.0 {
		return "High"
	}
	return "Invalid Score Value"
}
