package hydrator

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	nexposeHost = "http://nexpose.com"
)

type errReader struct {
	Error error
}

func (r *errReader) Read(_ []byte) (int, error) {
	return 0, r.Error
}

type requestURLMatcher struct {
	URL string
}

func (r *requestURLMatcher) Matches(x interface{}) bool {
	req, ok := x.(*http.Request)
	if !ok {
		return false
	}
	if req.URL.String() != r.URL {
		return false
	}
	return true
}

func (r *requestURLMatcher) String() string {
	return "Compares request URL for equality."
}

func TestFetchVulnerabilitySolutions(t *testing.T) {
	tests := []struct {
		name              string
		response          *http.Response
		reqError          error
		expectedError     bool
		expectedSolutions []string
	}{
		{
			"request error",
			nil,
			fmt.Errorf("error making request"),
			true,
			nil,
		},
		{
			"io error",
			&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf("io read error")})},
			nil,
			true,
			nil,
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`)))},
			nil,
			true,
			nil,
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"links": [], "resources": ["cve1", "cve2"]}`)))},
			nil,
			false,
			[]string{"cve1", "cve2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestURLMatcher{URL: "http://nexpose.com/api/3/vulnerabilities/vulnID/solutions"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				Client: &http.Client{Transport: mockRT},
				Host:   clientURL,
			}

			solutions, err := client.FetchVulnerabilitySolutions(context.Background(), "vulnID")

			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.ElementsMatch(tt, test.expectedSolutions, solutions)
			}
		})
	}
}

func TestFetchSolution(t *testing.T) {
	tests := []struct {
		name               string
		response           *http.Response
		reqError           error
		expectedError      bool
		expectedResolution string
	}{
		{
			"request error",
			nil,
			fmt.Errorf("error making request"),
			true,
			"",
		},
		{
			"io error",
			&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf("io read error")})},
			nil,
			true,
			"",
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`)))},
			nil,
			true,
			"",
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"steps": {"text": "here is how to fix that cve"}}`)))},
			nil,
			false,
			"here is how to fix that cve",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestURLMatcher{URL: "http://nexpose.com/api/3/solutions/solutionID"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				Client: &http.Client{Transport: mockRT},
				Host:   clientURL,
			}

			resolution, err := client.FetchSolution(context.Background(), "solutionID")

			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.Equal(tt, test.expectedResolution, resolution)
			}
		})
	}
}
func TestFetchVulnerabilityDetails(t *testing.T) {
	tests := []struct {
		name                string
		response            *http.Response
		reqError            error
		expectedError       bool
		expectedVulnDetails NexposeVulnerability
	}{
		{
			"request error",
			nil,
			fmt.Errorf("error making request"),
			true,
			NexposeVulnerability{},
		},
		{
			"io error",
			&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf("io read error")})},
			nil,
			true,
			NexposeVulnerability{},
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`)))},
			nil,
			true,
			NexposeVulnerability{},
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"title": "myVuln", "description": {"text": "vuln description"}, "cvss": {"v2": {"score": 7.5}}}`)))},
			nil,
			false,
			NexposeVulnerability{
				Title:          "myVuln",
				Description:    "vuln description",
				CvssV2Score:    7.5,
				CvssV2Severity: "High",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestURLMatcher{URL: "http://nexpose.com/api/3/vulnerabilities/vulnID"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				Client: &http.Client{Transport: mockRT},
				Host:   clientURL,
			}

			vulnDetails, err := client.FetchVulnerabilityDetails(context.Background(), "vulnID")

			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.Equal(tt, test.expectedVulnDetails, vulnDetails)
			}
		})
	}
}

func TestFetchAssetVulnerabilities(t *testing.T) {
	type response struct {
		res *http.Response
		err error
	}

	tests := []struct {
		name                      string
		responses                 []response
		expectedError             bool
		expectedNexposeAssetVulns []NexposeAssetVulnerability
	}{
		{
			"request error",
			[]response{
				response{
					nil,
					fmt.Errorf("error making request"),
				},
			},
			true,
			nil,
		},
		{
			"io error",
			[]response{
				response{
					&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf("io read error")})},
					nil,
				},
			},
			true,
			nil,
		},
		{
			"invalid json error",
			[]response{
				response{
					&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf(`{notjson}`)})},
					nil,
				},
			},
			true,
			nil,
		},
		{
			"single page response",
			[]response{
				response{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"totalPages": 1, "totalResources": 1}, "resources": [{"id": "vuln1", "results": [{"port": 443, "protocol": "tcp"}]}]}`,
					)))},
					nil,
				},
			},
			false,
			[]NexposeAssetVulnerability{
				NexposeAssetVulnerability{
					ID: "vuln1",
					Results: []domain.AssessmentResult{
						domain.AssessmentResult{Port: 443, Protocol: "tcp"},
					},
				},
			},
		},
		{
			"multi page response",
			[]response{
				response{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"number": 0, "totalPages": 2, "totalResources": 2}, "resources": [{"id": "vuln1", "results": [{"port": 443, "protocol": "tcp"}]}]}`,
					)))},
					nil,
				},
				response{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"number": 1, "totalPages": 2, "totalResources": 2}, "resources": [{"id": "vuln2", "results": [{"port": 80, "protocol": "tcp"}]}]}`,
					)))},
					nil,
				},
			},
			false,
			[]NexposeAssetVulnerability{
				NexposeAssetVulnerability{
					ID: "vuln1",
					Results: []domain.AssessmentResult{
						domain.AssessmentResult{Port: 443, Protocol: "tcp"},
					},
				},
				NexposeAssetVulnerability{
					ID: "vuln2",
					Results: []domain.AssessmentResult{
						domain.AssessmentResult{Port: 80, Protocol: "tcp"},
					},
				},
			},
		},
		{
			"multi page error",
			[]response{
				response{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"number": 0, "totalPages": 2, "totalResources": 2}, "resources": [{"id": "vuln1", "results": [{"port": 443, "protocol": "tcp"}]}]}`,
					)))},
					nil,
				},
				response{
					nil,
					fmt.Errorf("response error"),
				},
			},
			true,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			calls := make([]*gomock.Call, 0, len(test.responses))
			for reqNum, response := range test.responses {
				calls = append(calls, mockRT.EXPECT().RoundTrip(
					&requestURLMatcher{URL: fmt.Sprintf("http://nexpose.com/api/3/assets/111111/vulnerabilities?page=%d&size=0", reqNum)},
				).Return(response.res, response.err))
			}
			gomock.InOrder(calls...)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				Client: &http.Client{Transport: mockRT},
				Host:   clientURL,
			}

			assetVulns, err := client.FetchAssetVulnerabilities(context.Background(), 111111)

			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.Equal(tt, test.expectedNexposeAssetVulns, assetVulns)
			}
		})
	}
}

func TestMakePagedAssetVulnerabilitiesRequest(t *testing.T) {
	tests := []struct {
		name                     string
		response                 *http.Response
		reqError                 error
		expectedError            bool
		expectedNexposeAssetVuln NexposeAssetVulnerability
	}{
		{
			"request error",
			nil,
			fmt.Errorf("error making request"),
			true,
			NexposeAssetVulnerability{},
		},
		{
			"io error",
			&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf("io read error")})},
			nil,
			true,
			NexposeAssetVulnerability{},
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`)))},
			nil,
			true,
			NexposeAssetVulnerability{},
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"resources": [{"id": "vuln1", "results": [{"port": 80, "protocol": "tcp"}]}]}`)))},
			nil,
			true,
			NexposeAssetVulnerability{ID: "vuln1", Results: []domain.AssessmentResult{domain.AssessmentResult{Port: 80, Protocol: "tcp"}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestURLMatcher{URL: "http://nexpose.com/api/3/assets/111111/vulnerabilities?page=1&size=0"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				Client: &http.Client{Transport: mockRT},
				Host:   clientURL,
			}

			assetVulnsChan := make(chan NexposeAssetVulnerability, 1)
			errorChan := make(chan error, 1)
			client.makePagedAssetVulnerabilitiesRequest(111111, 1, assetVulnsChan, errorChan)

			select {
			case err := <-errorChan:
				if test.expectedError {
					assert.NotNil(tt, err)
				} else {
					tt.Fatalf("Unexpected error: %s", err.Error())
				}
			case assetVuln := <-assetVulnsChan:
				assert.Equal(tt, test.expectedNexposeAssetVuln, assetVuln)
			}
		})
	}
}

func TestNewAssetVulnerabilitiesRequest(t *testing.T) {
	clientURL, _ := url.Parse(nexposeHost)
	client := NexposeClient{
		Host: clientURL,
	}

	req := client.newAssetVulnerabilitiesRequest(111111, 1)
	assert.Equal(t, "http://nexpose.com/api/3/assets/111111/vulnerabilities?page=1&size=0", req.URL.String())
}

func TestAssetVulnToNexposeAssetVuln(t *testing.T) {
	resource := resource{
		ID:      "vulnID",
		Results: []result{result{Port: 443, Protocol: "tcp"}, result{Port: 80, Protocol: "tcp"}},
	}
	nexposeAssetVuln := assetVulnToNexposeAssetVuln(resource)
	assert.Equal(
		t,
		NexposeAssetVulnerability{
			ID: "vulnID",
			Results: []domain.AssessmentResult{
				domain.AssessmentResult{Port: 443, Protocol: "tcp"},
				domain.AssessmentResult{Port: 80, Protocol: "tcp"},
			},
		},
		nexposeAssetVuln,
	)
}

func TestCvssSeverity(t *testing.T) {
	tests := []struct {
		score            float64
		expectedSeverity string
	}{
		{
			1.0,
			"Low",
		},
		{
			5.0,
			"Medium",
		},
		{
			8.0,
			"High",
		},
		{
			-1.0,
			"Invalid Score Value",
		},
	}

	for _, test := range tests {
		t.Run(test.expectedSeverity, func(tt *testing.T) {
			assert.Equal(tt, test.expectedSeverity, cvssV2Severity(test.score))
		})
	}
}
