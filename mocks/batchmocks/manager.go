// Code generated by mockery v2.16.0. DO NOT EDIT.

package batchmocks

import (
	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"
	batch "github.com/hyperledger/firefly/internal/batch"

	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *Manager) Close() {
	_m.Called()
}

// NewMessages provides a mock function with given fields:
func (_m *Manager) NewMessages() chan<- int64 {
	ret := _m.Called()

	var r0 chan<- int64
	if rf, ok := ret.Get(0).(func() chan<- int64); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(chan<- int64)
		}
	}

	return r0
}

// RegisterDispatcher provides a mock function with given fields: name, txType, msgTypes, handler, batchOptions
func (_m *Manager) RegisterDispatcher(name string, txType fftypes.FFEnum, msgTypes []fftypes.FFEnum, handler batch.DispatchHandler, batchOptions batch.DispatcherOptions) {
	_m.Called(name, txType, msgTypes, handler, batchOptions)
}

// Start provides a mock function with given fields:
func (_m *Manager) Start() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Status provides a mock function with given fields:
func (_m *Manager) Status() *batch.ManagerStatus {
	ret := _m.Called()

	var r0 *batch.ManagerStatus
	if rf, ok := ret.Get(0).(func() *batch.ManagerStatus); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*batch.ManagerStatus)
		}
	}

	return r0
}

// WaitStop provides a mock function with given fields:
func (_m *Manager) WaitStop() {
	_m.Called()
}

type mockConstructorTestingTNewManager interface {
	mock.TestingT
	Cleanup(func())
}

// NewManager creates a new instance of Manager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewManager(t mockConstructorTestingTNewManager) *Manager {
	mock := &Manager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
