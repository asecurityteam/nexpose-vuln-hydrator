package hydrator

import (
	"context"
	"fmt"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestBatchSolutionFetcher(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSolutionFetcher := NewMockSolutionFetcher(ctrl)
	mockSolutionFetcher.EXPECT().FetchSolution(gomock.Any(), "solution1").Return("solution-steps", nil)

	batchSolutionFetch := batchSolutionFetcher{mockSolutionFetcher}
	solutions, err := batchSolutionFetch.BatchFetchSolution(context.Background(), []string{"solution1"})
	assert.Nil(t, err)
	assert.ElementsMatch(t, []string{"solution-steps"}, solutions)
}

func TestBatchSolutionFetcherMultiple(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSolutionFetcher := NewMockSolutionFetcher(ctrl)
	mockSolutionFetcher.EXPECT().FetchSolution(gomock.Any(), "solution1").Return("solution1-steps", nil)
	mockSolutionFetcher.EXPECT().FetchSolution(gomock.Any(), "solution2").Return("solution2-steps", nil)

	batchSolutionFetch := batchSolutionFetcher{mockSolutionFetcher}
	solutions, err := batchSolutionFetch.BatchFetchSolution(context.Background(), []string{"solution1", "solution2"})
	assert.Nil(t, err)
	assert.ElementsMatch(t, []string{"solution1-steps", "solution2-steps"}, solutions)
}

func TestBatchSolutionFetcherError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSolutionFetcher := NewMockSolutionFetcher(ctrl)
	mockSolutionFetcher.EXPECT().FetchSolution(gomock.Any(), "solution1").Return("solution1-steps", nil)
	mockSolutionFetcher.EXPECT().FetchSolution(gomock.Any(), "solution2").Return("", fmt.Errorf("couldn't get solutions"))

	batchSolutionFetch := batchSolutionFetcher{mockSolutionFetcher}
	solutions, err := batchSolutionFetch.BatchFetchSolution(context.Background(), []string{"solution1", "solution2"})
	assert.NotNil(t, err)
	assert.Empty(t, solutions)
}

func TestBatchCheckFetcher(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCheckFetcher := NewMockCheckFetcher(ctrl)
	mockCheckFetcher.EXPECT().FetchCheck(gomock.Any(), "check1").Return(true, nil)

	batchCheckFetch := batchCheckFetcher{mockCheckFetcher}
	checks, err := batchCheckFetch.BatchFetchCheck(context.Background(), []string{"check1"})
	assert.Nil(t, err)
	assert.ElementsMatch(t, []bool{true}, checks)
}

func TestBatchCheckFetcherMultiple(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCheckFetcher := NewMockCheckFetcher(ctrl)
	mockCheckFetcher.EXPECT().FetchCheck(gomock.Any(), "check1").Return(true, nil)
	mockCheckFetcher.EXPECT().FetchCheck(gomock.Any(), "check2").Return(false, nil)

	batchCheckFetch := batchCheckFetcher{mockCheckFetcher}
	checks, err := batchCheckFetch.BatchFetchCheck(context.Background(), []string{"check1", "check2"})
	assert.Nil(t, err)
	assert.ElementsMatch(t, []bool{true, false}, checks)
}

func TestBatchCheckFetcherError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCheckFetcher := NewMockCheckFetcher(ctrl)
	mockCheckFetcher.EXPECT().FetchCheck(gomock.Any(), "check1").Return(false, nil)
	mockCheckFetcher.EXPECT().FetchCheck(gomock.Any(), "check2").Return(false, fmt.Errorf("couldn't get checks"))

	batchCheckFetch := batchCheckFetcher{mockCheckFetcher}
	checks, err := batchCheckFetch.BatchFetchCheck(context.Background(), []string{"check1", "check2"})
	assert.NotNil(t, err)
	assert.Empty(t, checks)
}

func TestHydrateAssetVulnerability(t *testing.T) {
	vulnID := "vulnID"
	tests := []struct {
		name                string
		detailsResult       NexposeVulnerability
		detailsErr          error
		solutionsResult     []string
		vulnSolutionsErr    error
		batchSolutionResult []string
		batchSolutionErr    error
		checksResult        []string
		vulnChecksErr       error
		batchCheckResult    []bool
		batchCheckErr       error
		expectedVulnDetails domain.VulnerabilityDetails
		expectedErr         bool
	}{
		{
			"success",
			NexposeVulnerability{
				CvssV2Score:    6.5,
				CvssV2Severity: "Medium",
				Description:    "medium severity vuln",
				Title:          "Vulnerability",
				Status:         "invulnerable",
			},
			nil,
			[]string{"solution1", "solution2"},
			nil,
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			[]string{"check1", "check2"},
			nil,
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{
				ID: "vulnID",
				Results: []domain.AssessmentResult{
					domain.AssessmentResult{Port: 443, Protocol: "tcp", Proof: "Some proof"},
				},
				CvssV2Score:    6.5,
				CvssV2Severity: "Medium",
				Description:    "medium severity vuln",
				Title:          "Vulnerability",
				Solutions:      []string{"solution1-steps", "solution2-steps"},
				Status:         "invulnerable",
				LocalCheck:     true,
			},
			false,
		},
		{
			"details fetch error",
			NexposeVulnerability{},
			fmt.Errorf("details fetch error"),
			[]string{"solution1", "solution2"},
			nil,
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			[]string{"check1", "check2"},
			nil,
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"vuln solutions fetch error",
			NexposeVulnerability{},
			nil,
			nil,
			fmt.Errorf("vuln solutions fetch error"),
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			[]string{"check1", "check2"},
			nil,
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"solutions fetch error",
			NexposeVulnerability{},
			nil,
			[]string{"solution1", "solution2"},
			nil,
			nil,
			fmt.Errorf("solutions fetch error"),
			[]string{"check1", "check2"},
			nil,
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"vuln checks fetch error",
			NexposeVulnerability{},
			nil,
			[]string{"solution1", "solution2"},
			nil,
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			nil,
			fmt.Errorf("vuln checks fetch error"),
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"checks fetch error",
			NexposeVulnerability{},
			nil,
			[]string{"solution1", "solution2"},
			nil,
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			[]string{"check1", "check2"},
			nil,
			nil,
			fmt.Errorf("checks fetch error"),
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"details and vuln solutions fetch error",
			NexposeVulnerability{},
			fmt.Errorf("details fetch error"),
			nil,
			fmt.Errorf("vuln solutions fetch error"),
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			[]string{"check1", "check2"},
			nil,
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"details and solutions fetch error",
			NexposeVulnerability{},
			fmt.Errorf("details fetch error"),
			[]string{"solution1", "solution2"},
			nil,
			[]string{"solution1-steps", "solution2-steps"},
			fmt.Errorf("solutions fetch error"),
			[]string{"check1", "check2"},
			nil,
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"details and vuln checks fetch error",
			NexposeVulnerability{},
			fmt.Errorf("details fetch error"),
			[]string{"solution1", "solution2"},
			nil,
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			nil,
			fmt.Errorf("vuln checks fetch error"),
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"details and checks fetch error",
			NexposeVulnerability{},
			fmt.Errorf("details fetch error"),
			[]string{"solution1", "solution2"},
			nil,
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			[]string{"check1", "check2"},
			nil,
			nil,
			fmt.Errorf("checks fetch error"),
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"details, vuln checks, and vuln solutions fetch error",
			NexposeVulnerability{},
			fmt.Errorf("details fetch error"),
			nil,
			fmt.Errorf("vuln solutions fetch error"),
			[]string{"solution1-steps", "solution2-steps"},
			nil,
			nil,
			fmt.Errorf("vuln checks fetch error"),
			[]bool{false, true},
			nil,
			domain.VulnerabilityDetails{},
			true,
		},
		{
			"details, checks, and solutions fetch error",
			NexposeVulnerability{},
			fmt.Errorf("details fetch error"),
			[]string{"solution1", "solution2"},
			nil,
			nil,
			fmt.Errorf("solutions fetch error"),
			[]string{"check1", "check2"},
			nil,
			nil,
			fmt.Errorf("checks fetch error"),
			domain.VulnerabilityDetails{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			ctrl := gomock.NewController(t)
			mockVulnDetailsFetcher := NewMockVulnerabilityDetailsFetcher(ctrl)
			mockVulnSolutionsFetcher := NewMockVulnerabilitySolutionsFetcher(ctrl)
			mockBatchSolutionsFetcher := NewMockBatchSolutionFetcher(ctrl)
			mockVulnChecksFetcher := NewMockVulnerabilityChecksFetcher(ctrl)
			mockBatchChecksFetcher := NewMockBatchCheckFetcher(ctrl)

			mockVulnDetailsFetcher.EXPECT().FetchVulnerabilityDetails(gomock.Any(), vulnID).Return(test.detailsResult, test.detailsErr).
				MinTimes(0).MaxTimes(1)
			mockVulnSolutionsFetcher.EXPECT().FetchVulnerabilitySolutions(gomock.Any(), vulnID).Return(test.solutionsResult, test.vulnSolutionsErr).
				MinTimes(0).MaxTimes(1)
			mockBatchSolutionsFetcher.EXPECT().BatchFetchSolution(gomock.Any(), test.solutionsResult).Return(test.batchSolutionResult, test.batchSolutionErr).
				MinTimes(0).MaxTimes(1)
			mockVulnChecksFetcher.EXPECT().FetchVulnerabilityChecks(gomock.Any(), vulnID).Return(test.checksResult, test.vulnChecksErr).
				MinTimes(0).MaxTimes(1)
			mockBatchChecksFetcher.EXPECT().BatchFetchCheck(gomock.Any(), test.checksResult).Return(test.batchCheckResult, test.batchCheckErr).
				MinTimes(0).MaxTimes(1)

			assetVulnHydrator := assetVulnerabilityHydrator{
				VulnerabilityDetailsFetcher:   mockVulnDetailsFetcher,
				VulnerabilitySolutionsFetcher: mockVulnSolutionsFetcher,
				VulnerabilityChecksFetcher:    mockVulnChecksFetcher,
				BatchSolutionFetcher:          mockBatchSolutionsFetcher,
				BatchCheckFetcher:             mockBatchChecksFetcher,
			}

			hydratedVuln, err := assetVulnHydrator.HydrateAssetVulnerability(
				context.Background(),
				NexposeAssetVulnerability{
					ID:      vulnID,
					Results: []domain.AssessmentResult{domain.AssessmentResult{Port: 443, Protocol: "tcp", Proof: "Some proof"}},
					Status:  "invulnerable",
				},
			)
			if test.expectedErr {
				assert.NotNil(tt, err)
			} else {
				assert.Equal(tt, test.expectedVulnDetails, hydratedVuln)
				assert.Nil(tt, err)
			}
		})
	}
}

func TestBatchAssetVulnerabilityHydratorSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAssetVulnerabilityHydrator := NewMockAssetVulnerabilityHydrator(ctrl)
	mockAssetVulnerabilityHydrator.EXPECT().HydrateAssetVulnerability(gomock.Any(), gomock.Any()).Return(domain.VulnerabilityDetails{ID: "vuln1"}, nil)

	batchAssetVulnHydrator := batchAssetVulnerabilityHydrator{mockAssetVulnerabilityHydrator}
	vulnDetails, err := batchAssetVulnHydrator.BatchHydrateAssetVulnerabilities(
		context.Background(),
		[]NexposeAssetVulnerability{
			NexposeAssetVulnerability{
				ID: "vuln1",
			},
		},
	)

	assert.Nil(t, err)
	assert.NotEmpty(t, vulnDetails)
}

func TestBatchAssetVulnerabilityHydratorMultiple(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAssetVulnerabilityHydrator := NewMockAssetVulnerabilityHydrator(ctrl)
	mockAssetVulnerabilityHydrator.EXPECT().HydrateAssetVulnerability(gomock.Any(), gomock.Any()).Return(domain.VulnerabilityDetails{ID: "vuln1"}, nil)
	mockAssetVulnerabilityHydrator.EXPECT().HydrateAssetVulnerability(gomock.Any(), gomock.Any()).Return(domain.VulnerabilityDetails{ID: "vuln2"}, nil)

	batchAssetVulnHydrator := batchAssetVulnerabilityHydrator{mockAssetVulnerabilityHydrator}
	vulnDetails, err := batchAssetVulnHydrator.BatchHydrateAssetVulnerabilities(
		context.Background(),
		[]NexposeAssetVulnerability{
			NexposeAssetVulnerability{
				ID: "vuln1",
			},
			NexposeAssetVulnerability{
				ID: "vuln2",
			},
		},
	)

	assert.Nil(t, err)
	assert.Len(t, vulnDetails, 2)
}

func TestBatchAssetVulnerabilityHydratorError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAssetVulnerabilityHydrator := NewMockAssetVulnerabilityHydrator(ctrl)
	mockAssetVulnerabilityHydrator.EXPECT().HydrateAssetVulnerability(gomock.Any(), gomock.Any()).Return(domain.VulnerabilityDetails{}, fmt.Errorf("hydration error"))

	batchAssetVulnHydrator := batchAssetVulnerabilityHydrator{mockAssetVulnerabilityHydrator}
	vulnDetails, err := batchAssetVulnHydrator.BatchHydrateAssetVulnerabilities(
		context.Background(),
		[]NexposeAssetVulnerability{
			NexposeAssetVulnerability{
				ID: "vuln1",
			},
		},
	)

	assert.NotNil(t, err)
	assert.Nil(t, vulnDetails)
}

func TestAnyTrue(t *testing.T) {
	tests := []struct {
		name           string
		input          []bool
		expectedOutput bool
	}{
		{
			"empty slice",
			[]bool{},
			false,
		},
		{
			"single true",
			[]bool{true},
			true,
		},
		{
			"single false",
			[]bool{},
			false,
		},
		{
			"multiple contains true",
			[]bool{false, false, true},
			true,
		},
		{
			"multiple does not contain true",
			[]bool{false, false, false},
			false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			output := anyTrue(test.input)
			assert.Equal(tt, test.expectedOutput, output)
		})
	}
}
