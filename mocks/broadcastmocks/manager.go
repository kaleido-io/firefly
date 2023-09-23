// Code generated by mockery v2.33.2. DO NOT EDIT.

package broadcastmocks

import (
	context "context"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"
	core "github.com/hyperledger/firefly/pkg/core"

	mock "github.com/stretchr/testify/mock"

	syncasync "github.com/hyperledger/firefly/internal/syncasync"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// BroadcastMessage provides a mock function with given fields: ctx, in, waitConfirm
func (_m *Manager) BroadcastMessage(ctx context.Context, in *core.MessageInOut, waitConfirm bool) (*core.Message, error) {
	ret := _m.Called(ctx, in, waitConfirm)

	var r0 *core.Message
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.MessageInOut, bool) (*core.Message, error)); ok {
		return rf(ctx, in, waitConfirm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.MessageInOut, bool) *core.Message); ok {
		r0 = rf(ctx, in, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Message)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.MessageInOut, bool) error); ok {
		r1 = rf(ctx, in, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
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

// NewBroadcast provides a mock function with given fields: in
func (_m *Manager) NewBroadcast(in *core.MessageInOut) syncasync.Sender {
	ret := _m.Called(in)

	var r0 syncasync.Sender
	if rf, ok := ret.Get(0).(func(*core.MessageInOut) syncasync.Sender); ok {
		r0 = rf(in)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(syncasync.Sender)
		}
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

// PublishDataBlob provides a mock function with given fields: ctx, id, idempotencyKey
func (_m *Manager) PublishDataBlob(ctx context.Context, id string, idempotencyKey core.IdempotencyKey) (*core.Data, error) {
	ret := _m.Called(ctx, id, idempotencyKey)

	var r0 *core.Data
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, core.IdempotencyKey) (*core.Data, error)); ok {
		return rf(ctx, id, idempotencyKey)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, core.IdempotencyKey) *core.Data); ok {
		r0 = rf(ctx, id, idempotencyKey)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Data)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, core.IdempotencyKey) error); ok {
		r1 = rf(ctx, id, idempotencyKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PublishDataValue provides a mock function with given fields: ctx, id, idempotencyKey
func (_m *Manager) PublishDataValue(ctx context.Context, id string, idempotencyKey core.IdempotencyKey) (*core.Data, error) {
	ret := _m.Called(ctx, id, idempotencyKey)

	var r0 *core.Data
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, core.IdempotencyKey) (*core.Data, error)); ok {
		return rf(ctx, id, idempotencyKey)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, core.IdempotencyKey) *core.Data); ok {
		r0 = rf(ctx, id, idempotencyKey)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Data)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, core.IdempotencyKey) error); ok {
		r1 = rf(ctx, id, idempotencyKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RunOperation provides a mock function with given fields: ctx, op
func (_m *Manager) RunOperation(ctx context.Context, op *core.PreparedOperation) (fftypes.JSONObject, core.OpPhase, error) {
	ret := _m.Called(ctx, op)

	var r0 fftypes.JSONObject
	var r1 core.OpPhase
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.PreparedOperation) (fftypes.JSONObject, core.OpPhase, error)); ok {
		return rf(ctx, op)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.PreparedOperation) fftypes.JSONObject); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.JSONObject)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.PreparedOperation) core.OpPhase); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Get(1).(core.OpPhase)
	}

	if rf, ok := ret.Get(2).(func(context.Context, *core.PreparedOperation) error); ok {
		r2 = rf(ctx, op)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
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
