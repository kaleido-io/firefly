// Code generated by mockery v2.26.1. DO NOT EDIT.

package multipartymocks

import (
	context "context"

	blockchain "github.com/hyperledger/firefly/pkg/blockchain"

	core "github.com/hyperledger/firefly/pkg/core"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	multiparty "github.com/hyperledger/firefly/internal/multiparty"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// ConfigureContract provides a mock function with given fields: ctx
func (_m *Manager) ConfigureContract(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetNetworkVersion provides a mock function with given fields:
func (_m *Manager) GetNetworkVersion() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// LocalNode provides a mock function with given fields:
func (_m *Manager) LocalNode() multiparty.LocalNode {
	ret := _m.Called()

	var r0 multiparty.LocalNode
	if rf, ok := ret.Get(0).(func() multiparty.LocalNode); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(multiparty.LocalNode)
	}

	return r0
}

// Name provides a mock function with given fields:
func (_m *Manager) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// PrepareOperation provides a mock function with given fields: ctx, op
func (_m *Manager) PrepareOperation(ctx context.Context, op *core.Operation) (*core.PreparedOperation, error) {
	ret := _m.Called(ctx, op)

	var r0 *core.PreparedOperation
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Operation) (*core.PreparedOperation, error)); ok {
		return rf(ctx, op)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.Operation) *core.PreparedOperation); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.PreparedOperation)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.Operation) error); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RootOrg provides a mock function with given fields:
func (_m *Manager) RootOrg() multiparty.RootOrg {
	ret := _m.Called()

	var r0 multiparty.RootOrg
	if rf, ok := ret.Get(0).(func() multiparty.RootOrg); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(multiparty.RootOrg)
	}

	return r0
}

// RunOperation provides a mock function with given fields: ctx, op
func (_m *Manager) RunOperation(ctx context.Context, op *core.PreparedOperation) (fftypes.JSONObject, bool, error) {
	ret := _m.Called(ctx, op)

	var r0 fftypes.JSONObject
	var r1 bool
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.PreparedOperation) (fftypes.JSONObject, bool, error)); ok {
		return rf(ctx, op)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.PreparedOperation) fftypes.JSONObject); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.JSONObject)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.PreparedOperation) bool); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Get(1).(bool)
	}

	if rf, ok := ret.Get(2).(func(context.Context, *core.PreparedOperation) error); ok {
		r2 = rf(ctx, op)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// SubmitBatchPin provides a mock function with given fields: ctx, batch, contexts, payloadRef
func (_m *Manager) SubmitBatchPin(ctx context.Context, batch *core.BatchPersisted, contexts []*fftypes.Bytes32, payloadRef string) error {
	ret := _m.Called(ctx, batch, contexts, payloadRef)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.BatchPersisted, []*fftypes.Bytes32, string) error); ok {
		r0 = rf(ctx, batch, contexts, payloadRef)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SubmitNetworkAction provides a mock function with given fields: ctx, signingKey, action
func (_m *Manager) SubmitNetworkAction(ctx context.Context, signingKey string, action *core.NetworkAction) error {
	ret := _m.Called(ctx, signingKey, action)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *core.NetworkAction) error); ok {
		r0 = rf(ctx, signingKey, action)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TerminateContract provides a mock function with given fields: ctx, location, termination
func (_m *Manager) TerminateContract(ctx context.Context, location *fftypes.JSONAny, termination *blockchain.Event) error {
	ret := _m.Called(ctx, location, termination)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.JSONAny, *blockchain.Event) error); ok {
		r0 = rf(ctx, location, termination)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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
