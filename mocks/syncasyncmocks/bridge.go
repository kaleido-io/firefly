// Code generated by mockery v2.53.0. DO NOT EDIT.

package syncasyncmocks

import (
	context "context"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"
	core "github.com/hyperledger/firefly/pkg/core"

	mock "github.com/stretchr/testify/mock"

	syncasync "github.com/hyperledger/firefly/internal/syncasync"

	system "github.com/hyperledger/firefly/internal/events/system"
)

// Bridge is an autogenerated mock type for the Bridge type
type Bridge struct {
	mock.Mock
}

// Init provides a mock function with given fields: sysevents
func (_m *Bridge) Init(sysevents system.EventInterface) {
	_m.Called(sysevents)
}

// WaitForDeployOperation provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForDeployOperation(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.Operation, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForDeployOperation")
	}

	var r0 *core.Operation
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.Operation, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.Operation); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Operation)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitForIdentity provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForIdentity(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.Identity, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForIdentity")
	}

	var r0 *core.Identity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.Identity, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.Identity); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitForInvokeOperation provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForInvokeOperation(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.Operation, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForInvokeOperation")
	}

	var r0 *core.Operation
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.Operation, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.Operation); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Operation)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitForMessage provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForMessage(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.Message, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForMessage")
	}

	var r0 *core.Message
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.Message, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.Message); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Message)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitForReply provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForReply(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.MessageInOut, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForReply")
	}

	var r0 *core.MessageInOut
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.MessageInOut, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.MessageInOut); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.MessageInOut)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitForTokenApproval provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForTokenApproval(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.TokenApproval, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForTokenApproval")
	}

	var r0 *core.TokenApproval
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.TokenApproval, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.TokenApproval); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenApproval)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitForTokenPool provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForTokenPool(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.TokenPool, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForTokenPool")
	}

	var r0 *core.TokenPool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.TokenPool, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.TokenPool); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenPool)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitForTokenTransfer provides a mock function with given fields: ctx, id, send
func (_m *Bridge) WaitForTokenTransfer(ctx context.Context, id *fftypes.UUID, send syncasync.SendFunction) (*core.TokenTransfer, error) {
	ret := _m.Called(ctx, id, send)

	if len(ret) == 0 {
		panic("no return value specified for WaitForTokenTransfer")
	}

	var r0 *core.TokenTransfer
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) (*core.TokenTransfer, error)); ok {
		return rf(ctx, id, send)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) *core.TokenTransfer); ok {
		r0 = rf(ctx, id, send)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenTransfer)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, syncasync.SendFunction) error); ok {
		r1 = rf(ctx, id, send)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewBridge creates a new instance of Bridge. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewBridge(t interface {
	mock.TestingT
	Cleanup(func())
}) *Bridge {
	mock := &Bridge{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
