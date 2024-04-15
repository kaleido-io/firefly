// Code generated by mockery v2.40.1. DO NOT EDIT.

package shareddownloadmocks

import (
	context "context"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"
	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// InitiateDownloadBatch provides a mock function with given fields: ctx, tx, payloadRef, idempotentSubmit
func (_m *Manager) InitiateDownloadBatch(ctx context.Context, tx *fftypes.UUID, payloadRef string, idempotentSubmit bool) error {
	ret := _m.Called(ctx, tx, payloadRef, idempotentSubmit)

	if len(ret) == 0 {
		panic("no return value specified for InitiateDownloadBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, string, bool) error); ok {
		r0 = rf(ctx, tx, payloadRef, idempotentSubmit)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InitiateDownloadBlob provides a mock function with given fields: ctx, tx, dataID, payloadRef, idempotentSubmit
func (_m *Manager) InitiateDownloadBlob(ctx context.Context, tx *fftypes.UUID, dataID *fftypes.UUID, payloadRef string, idempotentSubmit bool) error {
	ret := _m.Called(ctx, tx, dataID, payloadRef, idempotentSubmit)

	if len(ret) == 0 {
		panic("no return value specified for InitiateDownloadBlob")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, *fftypes.UUID, string, bool) error); ok {
		r0 = rf(ctx, tx, dataID, payloadRef, idempotentSubmit)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Start provides a mock function with given fields:
func (_m *Manager) Start() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Start")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WaitStop provides a mock function with given fields:
func (_m *Manager) WaitStop() {
	_m.Called()
}

// NewManager creates a new instance of Manager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *Manager {
	mock := &Manager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
