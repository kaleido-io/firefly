// Code generated by mockery v1.0.0. DO NOT EDIT.

package privatemessagingmocks

import (
	context "context"

	core "github.com/hyperledger/firefly/pkg/core"
	database "github.com/hyperledger/firefly/pkg/database"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	sysmessaging "github.com/hyperledger/firefly/internal/sysmessaging"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// EnsureLocalGroup provides a mock function with given fields: ctx, group
func (_m *Manager) EnsureLocalGroup(ctx context.Context, group *core.Group) (bool, error) {
	ret := _m.Called(ctx, group)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, *core.Group) bool); ok {
		r0 = rf(ctx, group)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.Group) error); ok {
		r1 = rf(ctx, group)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetGroupByID provides a mock function with given fields: ctx, id
func (_m *Manager) GetGroupByID(ctx context.Context, id string) (*core.Group, error) {
	ret := _m.Called(ctx, id)

	var r0 *core.Group
	if rf, ok := ret.Get(0).(func(context.Context, string) *core.Group); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Group)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetGroups provides a mock function with given fields: ctx, filter
func (_m *Manager) GetGroups(ctx context.Context, filter database.AndFilter) ([]*core.Group, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*core.Group
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*core.Group); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.Group)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, database.AndFilter) error); ok {
		r2 = rf(ctx, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
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

// NewMessage provides a mock function with given fields: msg
func (_m *Manager) NewMessage(msg *core.MessageInOut) sysmessaging.MessageSender {
	ret := _m.Called(msg)

	var r0 sysmessaging.MessageSender
	if rf, ok := ret.Get(0).(func(*core.MessageInOut) sysmessaging.MessageSender); ok {
		r0 = rf(msg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(sysmessaging.MessageSender)
		}
	}

	return r0
}

// PrepareOperation provides a mock function with given fields: ctx, op
func (_m *Manager) PrepareOperation(ctx context.Context, op *core.Operation) (*core.PreparedOperation, error) {
	ret := _m.Called(ctx, op)

	var r0 *core.PreparedOperation
	if rf, ok := ret.Get(0).(func(context.Context, *core.Operation) *core.PreparedOperation); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.PreparedOperation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.Operation) error); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RequestReply provides a mock function with given fields: ctx, request
func (_m *Manager) RequestReply(ctx context.Context, request *core.MessageInOut) (*core.MessageInOut, error) {
	ret := _m.Called(ctx, request)

	var r0 *core.MessageInOut
	if rf, ok := ret.Get(0).(func(context.Context, *core.MessageInOut) *core.MessageInOut); ok {
		r0 = rf(ctx, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.MessageInOut)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.MessageInOut) error); ok {
		r1 = rf(ctx, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResolveInitGroup provides a mock function with given fields: ctx, msg
func (_m *Manager) ResolveInitGroup(ctx context.Context, msg *core.Message) (*core.Group, error) {
	ret := _m.Called(ctx, msg)

	var r0 *core.Group
	if rf, ok := ret.Get(0).(func(context.Context, *core.Message) *core.Group); ok {
		r0 = rf(ctx, msg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Group)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.Message) error); ok {
		r1 = rf(ctx, msg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RunOperation provides a mock function with given fields: ctx, op
func (_m *Manager) RunOperation(ctx context.Context, op *core.PreparedOperation) (fftypes.JSONObject, bool, error) {
	ret := _m.Called(ctx, op)

	var r0 fftypes.JSONObject
	if rf, ok := ret.Get(0).(func(context.Context, *core.PreparedOperation) fftypes.JSONObject); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.JSONObject)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(context.Context, *core.PreparedOperation) bool); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, *core.PreparedOperation) error); ok {
		r2 = rf(ctx, op)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// SendMessage provides a mock function with given fields: ctx, in, waitConfirm
func (_m *Manager) SendMessage(ctx context.Context, in *core.MessageInOut, waitConfirm bool) (*core.Message, error) {
	ret := _m.Called(ctx, in, waitConfirm)

	var r0 *core.Message
	if rf, ok := ret.Get(0).(func(context.Context, *core.MessageInOut, bool) *core.Message); ok {
		r0 = rf(ctx, in, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.MessageInOut, bool) error); ok {
		r1 = rf(ctx, in, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
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
