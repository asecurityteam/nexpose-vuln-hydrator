// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/domain/hydrator.go

// Package v1 is a generated GoMock package.
package v1

import (
	context "context"
	domain "github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockHydrator is a mock of Hydrator interface
type MockHydrator struct {
	ctrl     *gomock.Controller
	recorder *MockHydratorMockRecorder
}

// MockHydratorMockRecorder is the mock recorder for MockHydrator
type MockHydratorMockRecorder struct {
	mock *MockHydrator
}

// NewMockHydrator creates a new mock instance
func NewMockHydrator(ctrl *gomock.Controller) *MockHydrator {
	mock := &MockHydrator{ctrl: ctrl}
	mock.recorder = &MockHydratorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockHydrator) EXPECT() *MockHydratorMockRecorder {
	return m.recorder
}

// HydrateVulnerabilities mocks base method
func (m *MockHydrator) HydrateVulnerabilities(arg0 context.Context, arg1 domain.Asset) (domain.AssetVulnerabilityDetails, error) {
	ret := m.ctrl.Call(m, "HydrateVulnerabilities", arg0, arg1)
	ret0, _ := ret[0].(domain.AssetVulnerabilityDetails)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HydrateVulnerabilities indicates an expected call of HydrateVulnerabilities
func (mr *MockHydratorMockRecorder) HydrateVulnerabilities(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HydrateVulnerabilities", reflect.TypeOf((*MockHydrator)(nil).HydrateVulnerabilities), arg0, arg1)
}