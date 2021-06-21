// Code generated by mockery v1.0.0. DO NOT EDIT.

package privatemessagingmocks

import (
	context "context"

	database "github.com/hyperledger-labs/firefly/pkg/database"
	fftypes "github.com/hyperledger-labs/firefly/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// EnsureLocalGroup provides a mock function with given fields: ctx, group
func (_m *Manager) EnsureLocalGroup(ctx context.Context, group *fftypes.Group) error {
	ret := _m.Called(ctx, group)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.Group) error); ok {
		r0 = rf(ctx, group)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetGroupByID provides a mock function with given fields: ctx, id
func (_m *Manager) GetGroupByID(ctx context.Context, id string) (*fftypes.Group, error) {
	ret := _m.Called(ctx, id)

	var r0 *fftypes.Group
	if rf, ok := ret.Get(0).(func(context.Context, string) *fftypes.Group); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Group)
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
func (_m *Manager) GetGroups(ctx context.Context, filter database.AndFilter) ([]*fftypes.Group, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*fftypes.Group
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*fftypes.Group); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Group)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, database.AndFilter) error); ok {
		r1 = rf(ctx, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResolveInitGroup provides a mock function with given fields: ctx, msg
func (_m *Manager) ResolveInitGroup(ctx context.Context, msg *fftypes.Message) (*fftypes.Group, error) {
	ret := _m.Called(ctx, msg)

	var r0 *fftypes.Group
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.Message) *fftypes.Group); ok {
		r0 = rf(ctx, msg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Group)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.Message) error); ok {
		r1 = rf(ctx, msg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SendMessage provides a mock function with given fields: ctx, ns, in
func (_m *Manager) SendMessage(ctx context.Context, ns string, in *fftypes.MessageInput) (*fftypes.Message, error) {
	ret := _m.Called(ctx, ns, in)

	var r0 *fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.MessageInput) *fftypes.Message); ok {
		r0 = rf(ctx, ns, in)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.MessageInput) error); ok {
		r1 = rf(ctx, ns, in)
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
