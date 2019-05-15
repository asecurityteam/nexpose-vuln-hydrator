package hydrator

import (
	"context"
	"encoding/json"
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
}

// NexposeVulnerability represents the relevant fields from a Nexpose Vulnerability
type NexposeVulnerability struct {
	CvssV2Score    float64
	CvssV2Severity string
	Description    string
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
	Client   *http.Client
	Host     *url.URL
	Username string
	Password string
	PageSize int
}

// FetchVulnerabilitySolutions fetches the solutions to a particular vulnerability
func (n *NexposeClient) FetchVulnerabilitySolutions(ctx context.Context, vulnID string) ([]string, error) {
	u, _ := url.Parse(n.Host.String())
	u.Path = path.Join("api", "3", "vulnerabilities", vulnID, "solutions")
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	req.SetBasicAuth(n.Username, n.Password)

	res, err := n.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var solutions vulnerabilitySolutions
	err = json.Unmarshal(body, &solutions)
	if err != nil {
		return nil, err
	}
	return solutions.Resources, nil
}

// FetchSolution fetches details about a particular solution
func (n *NexposeClient) FetchSolution(ctx context.Context, solutionID string) (string, error) {
	u, _ := url.Parse(n.Host.String())
	u.Path = path.Join("api", "3", "solutions", solutionID)
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	req.SetBasicAuth(n.Username, n.Password)
	res, err := n.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
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
	u, _ := url.Parse(n.Host.String())
	u.Path = path.Join("api", "3", "vulnerabilities", vulnID)
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	req.SetBasicAuth(n.Username, n.Password)
	res, err := n.Client.Do(req)
	if err != nil {
		return NexposeVulnerability{}, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return NexposeVulnerability{}, err
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
	req := n.newAssetVulnerabilitiesRequest(assetID, 0)
	res, err := n.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
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
		go n.makePagedAssetVulnerabilitiesRequest(assetID, curPage, assetVulnsChannel, errorChan)
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

func (n *NexposeClient) makePagedAssetVulnerabilitiesRequest(assetID int64, page int, assetVulnsChannel chan NexposeAssetVulnerability, errorChan chan error) {
	req := n.newAssetVulnerabilitiesRequest(assetID, page)
	req.SetBasicAuth(n.Username, n.Password)
	res, err := n.Client.Do(req)
	if err != nil {
		errorChan <- err
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errorChan <- err
		return
	}
	var assetVulns assetVulnerabilities
	err = json.Unmarshal(body, &assetVulns)
	if err != nil {
		errorChan <- err
		return
	}
	for _, resource := range assetVulns.Resources {
		assetVulnsChannel <- assetVulnToNexposeAssetVuln(resource)
	}
}

func (n *NexposeClient) newAssetVulnerabilitiesRequest(assetID int64, page int) *http.Request {
	u, _ := url.Parse(n.Host.String())
	u.Path = path.Join("api", "3", "assets", strconv.FormatInt(assetID, 10), "vulnerabilities")
	q := u.Query()
	q.Set(pageQueryParam, strconv.Itoa(page))
	q.Set(sizeQueryParam, strconv.Itoa(n.PageSize))
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	req.SetBasicAuth(n.Username, n.Password)
	return req
}

func assetVulnToNexposeAssetVuln(resource resource) NexposeAssetVulnerability {
	results := make([]domain.AssessmentResult, 0, len(resource.Results))
	for _, result := range resource.Results {
		results = append(results, domain.AssessmentResult{
			Port:     result.Port,
			Protocol: result.Protocol,
		})
	}
	return NexposeAssetVulnerability{
		ID:      resource.ID,
		Results: results,
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
