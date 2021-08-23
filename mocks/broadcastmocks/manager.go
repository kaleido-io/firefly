// Code generated by mockery v1.0.0. DO NOT EDIT.

package broadcastmocks

import (
	context "context"

	fftypes "github.com/hyperledger-labs/firefly/pkg/fftypes"
	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// BroadcastDatatype provides a mock function with given fields: ctx, ns, datatype, waitConfirm
func (_m *Manager) BroadcastDatatype(ctx context.Context, ns string, datatype *fftypes.Datatype, waitConfirm bool) (*fftypes.Message, error) {
	ret := _m.Called(ctx, ns, datatype, waitConfirm)

	var r0 *fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.Datatype, bool) *fftypes.Message); ok {
		r0 = rf(ctx, ns, datatype, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.Datatype, bool) error); ok {
		r1 = rf(ctx, ns, datatype, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BroadcastDefinition provides a mock function with given fields: ctx, def, signingIdentity, tag, waitConfirm
func (_m *Manager) BroadcastDefinition(ctx context.Context, def fftypes.Definition, signingIdentity *fftypes.Identity, tag fftypes.SystemTag, waitConfirm bool) (*fftypes.Message, error) {
	ret := _m.Called(ctx, def, signingIdentity, tag, waitConfirm)

	var r0 *fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, fftypes.Definition, *fftypes.Identity, fftypes.SystemTag, bool) *fftypes.Message); ok {
		r0 = rf(ctx, def, signingIdentity, tag, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, fftypes.Definition, *fftypes.Identity, fftypes.SystemTag, bool) error); ok {
		r1 = rf(ctx, def, signingIdentity, tag, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BroadcastMessage provides a mock function with given fields: ctx, ns, in, waitConfirm
func (_m *Manager) BroadcastMessage(ctx context.Context, ns string, in *fftypes.MessageInOut, waitConfirm bool) (*fftypes.Message, error) {
	ret := _m.Called(ctx, ns, in, waitConfirm)

	var r0 *fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.MessageInOut, bool) *fftypes.Message); ok {
		r0 = rf(ctx, ns, in, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.MessageInOut, bool) error); ok {
		r1 = rf(ctx, ns, in, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BroadcastMessageWithID provides a mock function with given fields: ctx, ns, id, unresolved, resolved, waitConfirm
func (_m *Manager) BroadcastMessageWithID(ctx context.Context, ns string, id *fftypes.UUID, unresolved *fftypes.MessageInOut, resolved *fftypes.Message, waitConfirm bool) (*fftypes.Message, error) {
	ret := _m.Called(ctx, ns, id, unresolved, resolved, waitConfirm)

	var r0 *fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.UUID, *fftypes.MessageInOut, *fftypes.Message, bool) *fftypes.Message); ok {
		r0 = rf(ctx, ns, id, unresolved, resolved, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.UUID, *fftypes.MessageInOut, *fftypes.Message, bool) error); ok {
		r1 = rf(ctx, ns, id, unresolved, resolved, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BroadcastNamespace provides a mock function with given fields: ctx, ns, waitConfirm
func (_m *Manager) BroadcastNamespace(ctx context.Context, ns *fftypes.Namespace, waitConfirm bool) (*fftypes.Message, error) {
	ret := _m.Called(ctx, ns, waitConfirm)

	var r0 *fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.Namespace, bool) *fftypes.Message); ok {
		r0 = rf(ctx, ns, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.Namespace, bool) error); ok {
		r1 = rf(ctx, ns, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNodeSigningIdentity provides a mock function with given fields: ctx
func (_m *Manager) GetNodeSigningIdentity(ctx context.Context) (*fftypes.Identity, error) {
	ret := _m.Called(ctx)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context) *fftypes.Identity); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
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

// WaitStop provides a mock function with given fields:
func (_m *Manager) WaitStop() {
	_m.Called()
}
