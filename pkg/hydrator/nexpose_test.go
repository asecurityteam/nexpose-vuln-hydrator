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

type requestMatcher struct {
	URL     string
	Headers []string
}

func (r *requestMatcher) Matches(x interface{}) bool {
	req, ok := x.(*http.Request)
	if !ok {
		return false
	}
	if req.URL.String() != r.URL {
		return false
	}
	for _, header := range r.Headers {
		if _, ok := req.Header[header]; !ok {
			return false
		}
	}
	return true
}

func (r *requestMatcher) String() string {
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
			&http.Response{StatusCode: 200},
			fmt.Errorf("error making request"),
			true,
			nil,
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`))), StatusCode: 200},
			nil,
			true,
			nil,
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"links": [], "resources": ["cve1", "cve2"]}`))), StatusCode: 200},
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
				&requestMatcher{URL: "http://nexpose.com/api/3/vulnerabilities/vulnID/solutions"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
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
			&http.Response{StatusCode: 200},
			fmt.Errorf("error making request"),
			true,
			"",
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`))), StatusCode: 200},
			nil,
			true,
			"",
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"steps": {"text": "here is how to fix that cve"}}`))), StatusCode: 200},
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
				&requestMatcher{URL: "http://nexpose.com/api/3/solutions/solutionID"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
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

func TestFetchVulnerabilityChecks(t *testing.T) {
	tests := []struct {
		name           string
		response       *http.Response
		reqError       error
		expectedError  bool
		expectedChecks []string
	}{
		{
			"request error",
			&http.Response{StatusCode: 200},
			fmt.Errorf("error making request"),
			true,
			nil,
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`))), StatusCode: 200},
			nil,
			true,
			nil,
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"links": [], "resources": ["check1", "check2"]}`))), StatusCode: 200},
			nil,
			false,
			[]string{"check1", "check2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestMatcher{URL: "http://nexpose.com/api/3/vulnerabilities/vulnID/checks"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
			}

			checks, err := client.FetchVulnerabilityChecks(context.Background(), "vulnID")

			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.ElementsMatch(tt, test.expectedChecks, checks)
			}
		})
	}
}

func TestFetchCheck(t *testing.T) {
	tests := []struct {
		name          string
		response      *http.Response
		reqError      error
		expectedError bool
		expectedValue bool
	}{
		{
			"request error",
			&http.Response{StatusCode: 200},
			fmt.Errorf("error making request"),
			true,
			false,
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`))), StatusCode: 200},
			nil,
			true,
			false,
		},
		{
			"success - negative case",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"id": "ssl-cve-2011-3389-beast", "links": [{"href": "https://nexpose.sec.internal.atlassian.com/api/3/vulnerability_checks/ssl-cve-2011-3389-beast", "rel": "self"}, {"id": "ssl-cve-2011-3389-beast", "href": "https://nexpose.sec.internal.atlassian.com/api/3/vulnerabilities/ssl-cve-2011-3389-beast", "rel": "Vulnerability"}], "plugin": "NetworkRemoteScanners", "potential": false, "requiresCredentials": true, "safe": true, "service": true, "unique": true, "vulnerability": "ssl-cve-2011-3389-beast"}`))), StatusCode: 200},
			nil,
			false,
			false,
		},
		{
			"success - positive case",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"id": "jre-vuln-cve-2018-2800", "links": [{"href": "https://nexpose.sec.internal.atlassian.com/api/3/vulnerability_checks/jre-vuln-cve-2018-2800", "rel": "self"}, {"id": "jre-vuln-cve-2018-2800", "href": "https://nexpose.sec.internal.atlassian.com/api/3/vulnerabilities/jre-vuln-cve-2018-2800", "rel": "Vulnerability"}], "plugin": "OracleJavaScanner", "potential": false, "requiresCredentials": true, "safe": true, "service": false, "unique": false, "vulnerability": "jre-vuln-cve-2018-2800"}`))), StatusCode: 200},
			nil,
			false,
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestMatcher{URL: "http://nexpose.com/api/3/vulnerability_checks/checkID"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
			}

			isLocalCheck, err := client.FetchCheck(context.Background(), "checkID")

			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.Equal(tt, test.expectedValue, isLocalCheck)
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
			&http.Response{StatusCode: 200},
			fmt.Errorf("error making request"),
			true,
			NexposeVulnerability{},
		},
		{
			"invalid json error",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`))), StatusCode: 200},
			nil,
			true,
			NexposeVulnerability{},
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{"title": "myVuln", "description": {"text": "vuln description"}, "cvss": {"v2": {"score": 7.5}}}`))), StatusCode: 200},
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
				&requestMatcher{URL: "http://nexpose.com/api/3/vulnerabilities/vulnID"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
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
				{
					&http.Response{StatusCode: 200},
					fmt.Errorf("error making request"),
				},
			},
			true,
			nil,
		},
		{
			"invalid json error",
			[]response{
				{
					&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf(`{notjson}`)}),
						StatusCode: 200},
					nil,
				},
			},
			true,
			nil,
		},
		{
			"single page response",
			[]response{
				{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"totalPages": 1, "totalResources": 1}, "resources": [{"id": "vuln1", "results": [{"port": 443, "protocol": "tcp", "proof": "some proof"}], "status": "vulnerable"}]}`,
					))),
						StatusCode: 200},
					nil,
				},
			},
			false,
			[]NexposeAssetVulnerability{
				{
					ID: "vuln1",
					Results: []domain.AssessmentResult{
						{Port: 443, Protocol: "tcp", Proof: "some proof"},
					},
					Status: "vulnerable",
				},
			},
		},
		{
			"multi page response",
			[]response{
				{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"number": 0, "totalPages": 2, "totalResources": 2}, "resources": [{"id": "vuln1", "results": [{"port": 443, "protocol": "tcp", "proof": "some proof"}], "status": "vulnerable"}]}`,
					))),
						StatusCode: 200},
					nil,
				},
				{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"number": 1, "totalPages": 2, "totalResources": 2}, "resources": [{"id": "vuln2", "results": [{"port": 80, "protocol": "tcp", "proof": "some proof"}], "status": "invulnerable"}]}`,
					))),
						StatusCode: 200},
					nil,
				},
			},
			false,
			[]NexposeAssetVulnerability{
				{
					ID: "vuln1",
					Results: []domain.AssessmentResult{
						{Port: 443, Protocol: "tcp", Proof: "some proof"},
					},
					Status: "vulnerable",
				},
				{
					ID: "vuln2",
					Results: []domain.AssessmentResult{
						{Port: 80, Protocol: "tcp", Proof: "some proof"},
					},
					Status: "invulnerable",
				},
			},
		},
		{
			"multi page error",
			[]response{
				{
					&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(
						`{"page": {"number": 0, "totalPages": 2, "totalResources": 2}, "resources": [{"id": "vuln1", "results": [{"port": 443, "protocol": "tcp", "proof": "some proof"}]}]}`,
					))),
						StatusCode: 200},
					nil,
				},
				{
					&http.Response{StatusCode: 200},
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
					&requestMatcher{URL: fmt.Sprintf("http://nexpose.com/api/3/assets/111111/vulnerabilities?page=%d&size=0", reqNum)},
				).Return(response.res, response.err))
			}
			gomock.InOrder(calls...)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
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
		name                      string
		response                  *http.Response
		reqError                  error
		expectedError             bool
		expectedNexposeAssetVulns []NexposeAssetVulnerability
	}{
		{
			"error",
			&http.Response{StatusCode: 200},
			fmt.Errorf("error"),
			true,
			nil,
		},
		{
			"invalid json error",
			&http.Response{
				Body: ioutil.NopCloser(bytes.NewBuffer([]byte(`{notjson}`))),
			},
			nil,
			true,
			nil,
		},
		{
			"success",
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(`{"resources": [{"id": "vuln1", "results": [{"port": 80, "protocol": "tcp", "proof": "some proof"}], "status": "vulnerable"}]}`))),
				StatusCode: 200,
			},
			nil,
			false,
			[]NexposeAssetVulnerability{
				{
					ID: "vuln1",
					Results: []domain.AssessmentResult{
						{
							Port:     80,
							Protocol: "tcp",
							Proof:    "some proof",
						},
					},
					Status: "vulnerable",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestMatcher{URL: "http://nexpose.com/api/3/assets/111111/vulnerabilities?page=1&size=0"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
			}

			assetVulns, err := client.makePagedAssetVulnerabilitiesRequest(111111, 1)

			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Nil(tt, err)
				assert.ElementsMatch(tt, test.expectedNexposeAssetVulns, assetVulns)
			}
		})
	}
}

func TestAssetVulnToNexposeAssetVuln(t *testing.T) {
	nexposeResource := resource{
		ID: "vulnID",
		Results: []result{
			{
				Port:     443,
				Protocol: "tcp",
				Proof:    "some proof",
			},
			{
				Port:     80,
				Protocol: "tcp",
				Proof:    "some proof",
			},
		},
		Status: "vulnerable",
	}
	nexposeAssetVuln := assetVulnToNexposeAssetVuln(nexposeResource)
	assert.Equal(
		t,
		NexposeAssetVulnerability{
			ID: "vulnID",
			Results: []domain.AssessmentResult{
				{Port: 443, Protocol: "tcp", Proof: "some proof"},
				{Port: 80, Protocol: "tcp", Proof: "some proof"},
			},
			Status: "vulnerable",
		},
		nexposeAssetVuln,
	)
}

func TestMakeNexposeRequest(t *testing.T) {
	tests := []struct {
		name          string
		response      *http.Response
		reqError      error
		expectedError bool
		expectedBody  []byte
	}{
		{
			"request error",
			&http.Response{StatusCode: 200},
			fmt.Errorf("error making request"),
			true,
			nil,
		},
		{
			"io error",
			&http.Response{Body: ioutil.NopCloser(&errReader{Error: fmt.Errorf("io read error")}), StatusCode: 200},
			nil,
			true,
			nil,
		},
		{
			"success",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte("response"))), StatusCode: 200},
			nil,
			false,
			[]byte("response"),
		},
		{
			"not 200",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(""))), StatusCode: 502},
			nil,
			true,
			nil,
		},
		{
			"also not 200",
			&http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(""))), StatusCode: 404},
			nil,
			true,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(
				&requestMatcher{URL: "http://nexpose.com/this/is/my/path?key1=value1"},
			).Return(test.response, test.reqError)
			clientURL, _ := url.Parse(nexposeHost)
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
			}

			body, err := client.makeNexposeRequest(map[string]string{"key1": "value1"}, "this", "is", "my", "path")
			if test.expectedError {
				assert.NotNil(tt, err)
			} else {
				assert.Equal(tt, test.expectedBody, body)
			}
		})
	}
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

func TestNexposeDependencyCheck(t *testing.T) {
	tests := []struct {
		name               string
		clientReturnStatus int
		expectedErr        bool
	}{
		{
			name:               "success",
			clientReturnStatus: http.StatusOK,
			expectedErr:        false,
		},
		{
			name:               "failure",
			clientReturnStatus: http.StatusTeapot,
			expectedErr:        true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			mockRT := NewMockRoundTripper(ctrl)
			mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
				Body:       ioutil.NopCloser(bytes.NewReader([]byte("🐖"))),
				StatusCode: test.clientReturnStatus,
			}, nil)
			clientURL, _ := url.Parse("http://localhost")
			client := NexposeClient{
				HTTPClient: &http.Client{Transport: mockRT},
				Host:       clientURL,
			}
			err := client.CheckDependencies(context.Background())
			assert.Equal(tt, test.expectedErr, err != nil)
		})
	}
}
