// Code generated by mockery v2.26.1. DO NOT EDIT.

package dataexchangemocks

import (
	context "context"

	config "github.com/hyperledger/firefly-common/pkg/config"

	core "github.com/hyperledger/firefly/pkg/core"

	dataexchange "github.com/hyperledger/firefly/pkg/dataexchange"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	io "io"

	mock "github.com/stretchr/testify/mock"
)

// Plugin is an autogenerated mock type for the Plugin type
type Plugin struct {
	mock.Mock
}

// AddNode provides a mock function with given fields: ctx, networkNamespace, nodeName, peer
func (_m *Plugin) AddNode(ctx context.Context, networkNamespace string, nodeName string, peer fftypes.JSONObject) error {
	ret := _m.Called(ctx, networkNamespace, nodeName, peer)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, fftypes.JSONObject) error); ok {
		r0 = rf(ctx, networkNamespace, nodeName, peer)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Capabilities provides a mock function with given fields:
func (_m *Plugin) Capabilities() *dataexchange.Capabilities {
	ret := _m.Called()

	var r0 *dataexchange.Capabilities
	if rf, ok := ret.Get(0).(func() *dataexchange.Capabilities); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dataexchange.Capabilities)
		}
	}

	return r0
}

// DeleteBlob provides a mock function with given fields: ctx, payloadRef
func (_m *Plugin) DeleteBlob(ctx context.Context, payloadRef string) error {
	ret := _m.Called(ctx, payloadRef)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, payloadRef)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DownloadBlob provides a mock function with given fields: ctx, payloadRef
func (_m *Plugin) DownloadBlob(ctx context.Context, payloadRef string) (io.ReadCloser, error) {
	ret := _m.Called(ctx, payloadRef)

	var r0 io.ReadCloser
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (io.ReadCloser, error)); ok {
		return rf(ctx, payloadRef)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) io.ReadCloser); ok {
		r0 = rf(ctx, payloadRef)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, payloadRef)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetEndpointInfo provides a mock function with given fields: ctx, nodeName
func (_m *Plugin) GetEndpointInfo(ctx context.Context, nodeName string) (fftypes.JSONObject, error) {
	ret := _m.Called(ctx, nodeName)

	var r0 fftypes.JSONObject
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (fftypes.JSONObject, error)); ok {
		return rf(ctx, nodeName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) fftypes.JSONObject); ok {
		r0 = rf(ctx, nodeName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.JSONObject)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, nodeName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPeerID provides a mock function with given fields: peer
func (_m *Plugin) GetPeerID(peer fftypes.JSONObject) string {
	ret := _m.Called(peer)

	var r0 string
	if rf, ok := ret.Get(0).(func(fftypes.JSONObject) string); ok {
		r0 = rf(peer)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Init provides a mock function with given fields: ctx, cancelCtx, _a2
func (_m *Plugin) Init(ctx context.Context, cancelCtx context.CancelFunc, _a2 config.Section) error {
	ret := _m.Called(ctx, cancelCtx, _a2)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, context.CancelFunc, config.Section) error); ok {
		r0 = rf(ctx, cancelCtx, _a2)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InitConfig provides a mock function with given fields: _a0
func (_m *Plugin) InitConfig(_a0 config.Section) {
	_m.Called(_a0)
}

// Name provides a mock function with given fields:
func (_m *Plugin) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// SendMessage provides a mock function with given fields: ctx, nsOpID, peer, sender, data
func (_m *Plugin) SendMessage(ctx context.Context, nsOpID string, peer fftypes.JSONObject, sender fftypes.JSONObject, data []byte) error {
	ret := _m.Called(ctx, nsOpID, peer, sender, data)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, fftypes.JSONObject, fftypes.JSONObject, []byte) error); ok {
		r0 = rf(ctx, nsOpID, peer, sender, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetHandler provides a mock function with given fields: networkNamespace, nodeName, handler
func (_m *Plugin) SetHandler(networkNamespace string, nodeName string, handler dataexchange.Callbacks) {
	_m.Called(networkNamespace, nodeName, handler)
}

// SetOperationHandler provides a mock function with given fields: namespace, handler
func (_m *Plugin) SetOperationHandler(namespace string, handler core.OperationCallbacks) {
	_m.Called(namespace, handler)
}

// Start provides a mock function with given fields:
func (_m *Plugin) Start() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TransferBlob provides a mock function with given fields: ctx, nsOpID, peer, sender, payloadRef
func (_m *Plugin) TransferBlob(ctx context.Context, nsOpID string, peer fftypes.JSONObject, sender fftypes.JSONObject, payloadRef string) error {
	ret := _m.Called(ctx, nsOpID, peer, sender, payloadRef)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, fftypes.JSONObject, fftypes.JSONObject, string) error); ok {
		r0 = rf(ctx, nsOpID, peer, sender, payloadRef)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UploadBlob provides a mock function with given fields: ctx, ns, id, content
func (_m *Plugin) UploadBlob(ctx context.Context, ns string, id fftypes.UUID, content io.Reader) (string, *fftypes.Bytes32, int64, error) {
	ret := _m.Called(ctx, ns, id, content)

	var r0 string
	var r1 *fftypes.Bytes32
	var r2 int64
	var r3 error
	if rf, ok := ret.Get(0).(func(context.Context, string, fftypes.UUID, io.Reader) (string, *fftypes.Bytes32, int64, error)); ok {
		return rf(ctx, ns, id, content)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, fftypes.UUID, io.Reader) string); ok {
		r0 = rf(ctx, ns, id, content)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, fftypes.UUID, io.Reader) *fftypes.Bytes32); ok {
		r1 = rf(ctx, ns, id, content)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*fftypes.Bytes32)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, fftypes.UUID, io.Reader) int64); ok {
		r2 = rf(ctx, ns, id, content)
	} else {
		r2 = ret.Get(2).(int64)
	}

	if rf, ok := ret.Get(3).(func(context.Context, string, fftypes.UUID, io.Reader) error); ok {
		r3 = rf(ctx, ns, id, content)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

type mockConstructorTestingTNewPlugin interface {
	mock.TestingT
	Cleanup(func())
}

// NewPlugin creates a new instance of Plugin. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewPlugin(t mockConstructorTestingTNewPlugin) *Plugin {
	mock := &Plugin{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
