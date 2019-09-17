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
	_, err := batchSolutionFetch.BatchFetchSolution(context.Background(), []string{"solution1"})
	assert.Nil(t, err)
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
func TestHydrateAssetVulnerabilityDetailsFetchError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockVulnDetailsFetcher := NewMockVulnerabilityDetailsFetcher(ctrl)
	mockVulnSolutionsFetcher := NewMockVulnerabilitySolutionsFetcher(ctrl)
	mockBatchSolutionsFetcher := NewMockBatchSolutionFetcher(ctrl)

	mockVulnDetailsFetcher.EXPECT().
		FetchVulnerabilityDetails(gomock.Any(), "vulnID").
		Return(NexposeVulnerability{}, fmt.Errorf("details fetch error"))
	mockVulnSolutionsFetcher.EXPECT().FetchVulnerabilitySolutions(gomock.Any(), "vulnID").Return([]string{"solution1", "solution2"}, nil)
	mockBatchSolutionsFetcher.EXPECT().BatchFetchSolution(gomock.Any(), []string{"solution1", "solution2"}).Return([]string{"solution1-steps", "solution2-steps"}, nil)

	assetVulnHydrator := assetVulnerabilityHydrator{
		VulnerabilityDetailsFetcher:   mockVulnDetailsFetcher,
		VulnerabilitySolutionsFetcher: mockVulnSolutionsFetcher,
		BatchSolutionFetcher:          mockBatchSolutionsFetcher,
	}

	_, err := assetVulnHydrator.HydrateAssetVulnerability(
		context.Background(),
		NexposeAssetVulnerability{
			ID:      "vulnID",
			Results: []domain.AssessmentResult{domain.AssessmentResult{Port: 443, Protocol: "tcp", Proof: "Some proof"}},
			Status:  "vulnerable",
		},
	)
	assert.NotNil(t, err)
}

func TestHydrateAssetVulnerabilityVulnSolutionsFetchError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockVulnDetailsFetcher := NewMockVulnerabilityDetailsFetcher(ctrl)
	mockVulnSolutionsFetcher := NewMockVulnerabilitySolutionsFetcher(ctrl)
	mockBatchSolutionsFetcher := NewMockBatchSolutionFetcher(ctrl)

	mockVulnDetailsFetcher.EXPECT().
		FetchVulnerabilityDetails(gomock.Any(), "vulnID").
		Return(NexposeVulnerability{}, nil)
	mockVulnSolutionsFetcher.EXPECT().FetchVulnerabilitySolutions(gomock.Any(), "vulnID").Return([]string{}, fmt.Errorf("vuln solutions fetch error"))

	assetVulnHydrator := assetVulnerabilityHydrator{
		VulnerabilityDetailsFetcher:   mockVulnDetailsFetcher,
		VulnerabilitySolutionsFetcher: mockVulnSolutionsFetcher,
		BatchSolutionFetcher:          mockBatchSolutionsFetcher,
	}

	_, err := assetVulnHydrator.HydrateAssetVulnerability(
		context.Background(),
		NexposeAssetVulnerability{
			ID:      "vulnID",
			Results: []domain.AssessmentResult{domain.AssessmentResult{Port: 443, Protocol: "tcp", Proof: "Some proof"}},
			Status:  "vulnerable",
		},
	)
	assert.NotNil(t, err)
}

func TestHydrateAssetVulnerabilityBatchSolutionsFetchError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockVulnDetailsFetcher := NewMockVulnerabilityDetailsFetcher(ctrl)
	mockVulnSolutionsFetcher := NewMockVulnerabilitySolutionsFetcher(ctrl)
	mockBatchSolutionsFetcher := NewMockBatchSolutionFetcher(ctrl)

	mockVulnDetailsFetcher.EXPECT().
		FetchVulnerabilityDetails(gomock.Any(), "vulnID").
		Return(NexposeVulnerability{}, fmt.Errorf("details fetch error"))
	mockVulnSolutionsFetcher.EXPECT().FetchVulnerabilitySolutions(gomock.Any(), "vulnID").Return([]string{"solution1", "solution2"}, nil)
	mockBatchSolutionsFetcher.EXPECT().BatchFetchSolution(gomock.Any(), []string{"solution1", "solution2"}).Return([]string{}, fmt.Errorf("batch solution fetch error"))

	assetVulnHydrator := assetVulnerabilityHydrator{
		VulnerabilityDetailsFetcher:   mockVulnDetailsFetcher,
		VulnerabilitySolutionsFetcher: mockVulnSolutionsFetcher,
		BatchSolutionFetcher:          mockBatchSolutionsFetcher,
	}

	_, err := assetVulnHydrator.HydrateAssetVulnerability(
		context.Background(),
		NexposeAssetVulnerability{
			ID:      "vulnID",
			Results: []domain.AssessmentResult{domain.AssessmentResult{Port: 443, Protocol: "tcp", Proof: "Some proof"}},
			Status:  "vulnerable",
		},
	)
	assert.NotNil(t, err)
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

			mockVulnDetailsFetcher.EXPECT().FetchVulnerabilityDetails(gomock.Any(), vulnID).Return(test.detailsResult, test.detailsErr)
			mockVulnSolutionsFetcher.EXPECT().FetchVulnerabilitySolutions(gomock.Any(), vulnID).Return(test.solutionsResult, test.vulnSolutionsErr)
			mockBatchSolutionsFetcher.EXPECT().BatchFetchSolution(gomock.Any(), test.solutionsResult).Return(test.batchSolutionResult, test.batchSolutionErr)

			assetVulnHydrator := assetVulnerabilityHydrator{
				VulnerabilityDetailsFetcher:   mockVulnDetailsFetcher,
				VulnerabilitySolutionsFetcher: mockVulnSolutionsFetcher,
				BatchSolutionFetcher:          mockBatchSolutionsFetcher,
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
