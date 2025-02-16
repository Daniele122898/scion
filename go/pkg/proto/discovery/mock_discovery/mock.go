// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/pkg/proto/discovery (interfaces: DiscoveryServiceServer)

// Package mock_discovery is a generated GoMock package.
package mock_discovery

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	discovery "github.com/scionproto/scion/go/pkg/proto/discovery"
)

// MockDiscoveryServiceServer is a mock of DiscoveryServiceServer interface.
type MockDiscoveryServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockDiscoveryServiceServerMockRecorder
}

// MockDiscoveryServiceServerMockRecorder is the mock recorder for MockDiscoveryServiceServer.
type MockDiscoveryServiceServerMockRecorder struct {
	mock *MockDiscoveryServiceServer
}

// NewMockDiscoveryServiceServer creates a new mock instance.
func NewMockDiscoveryServiceServer(ctrl *gomock.Controller) *MockDiscoveryServiceServer {
	mock := &MockDiscoveryServiceServer{ctrl: ctrl}
	mock.recorder = &MockDiscoveryServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDiscoveryServiceServer) EXPECT() *MockDiscoveryServiceServerMockRecorder {
	return m.recorder
}

// ColibriServices mocks base method.
func (m *MockDiscoveryServiceServer) ColibriServices(arg0 context.Context, arg1 *discovery.ColibriServicesRequest) (*discovery.ColibriServicesResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ColibriServices", arg0, arg1)
	ret0, _ := ret[0].(*discovery.ColibriServicesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ColibriServices indicates an expected call of ColibriServices.
func (mr *MockDiscoveryServiceServerMockRecorder) ColibriServices(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ColibriServices", reflect.TypeOf((*MockDiscoveryServiceServer)(nil).ColibriServices), arg0, arg1)
}

// Gateways mocks base method.
func (m *MockDiscoveryServiceServer) Gateways(arg0 context.Context, arg1 *discovery.GatewaysRequest) (*discovery.GatewaysResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Gateways", arg0, arg1)
	ret0, _ := ret[0].(*discovery.GatewaysResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Gateways indicates an expected call of Gateways.
func (mr *MockDiscoveryServiceServerMockRecorder) Gateways(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Gateways", reflect.TypeOf((*MockDiscoveryServiceServer)(nil).Gateways), arg0, arg1)
}

// HiddenSegmentServices mocks base method.
func (m *MockDiscoveryServiceServer) HiddenSegmentServices(arg0 context.Context, arg1 *discovery.HiddenSegmentServicesRequest) (*discovery.HiddenSegmentServicesResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HiddenSegmentServices", arg0, arg1)
	ret0, _ := ret[0].(*discovery.HiddenSegmentServicesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HiddenSegmentServices indicates an expected call of HiddenSegmentServices.
func (mr *MockDiscoveryServiceServerMockRecorder) HiddenSegmentServices(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HiddenSegmentServices", reflect.TypeOf((*MockDiscoveryServiceServer)(nil).HiddenSegmentServices), arg0, arg1)
}
