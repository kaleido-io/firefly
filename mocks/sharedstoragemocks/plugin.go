<<<<<<< HEAD
// Code generated by mockery v2.40.2. DO NOT EDIT.
=======
// Code generated by mockery v2.42.1. DO NOT EDIT.
>>>>>>> origin/main

package sharedstoragemocks

import (
	context "context"

	config "github.com/hyperledger/firefly-common/pkg/config"

	io "io"

	mock "github.com/stretchr/testify/mock"

	sharedstorage "github.com/hyperledger/firefly/pkg/sharedstorage"
)

// Plugin is an autogenerated mock type for the Plugin type
type Plugin struct {
	mock.Mock
}

// Capabilities provides a mock function with given fields:
func (_m *Plugin) Capabilities() *sharedstorage.Capabilities {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Capabilities")
	}

	var r0 *sharedstorage.Capabilities
	if rf, ok := ret.Get(0).(func() *sharedstorage.Capabilities); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*sharedstorage.Capabilities)
		}
	}

	return r0
}

// DownloadData provides a mock function with given fields: ctx, payloadRef
func (_m *Plugin) DownloadData(ctx context.Context, payloadRef string) (io.ReadCloser, error) {
	ret := _m.Called(ctx, payloadRef)

	if len(ret) == 0 {
		panic("no return value specified for DownloadData")
	}

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

// Init provides a mock function with given fields: ctx, _a1
func (_m *Plugin) Init(ctx context.Context, _a1 config.Section) error {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Init")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, config.Section) error); ok {
		r0 = rf(ctx, _a1)
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

	if len(ret) == 0 {
		panic("no return value specified for Name")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// SetHandler provides a mock function with given fields: namespace, handler
func (_m *Plugin) SetHandler(namespace string, handler sharedstorage.Callbacks) {
	_m.Called(namespace, handler)
}

// UploadData provides a mock function with given fields: ctx, data
func (_m *Plugin) UploadData(ctx context.Context, data io.Reader) (string, error) {
	ret := _m.Called(ctx, data)

	if len(ret) == 0 {
		panic("no return value specified for UploadData")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, io.Reader) (string, error)); ok {
		return rf(ctx, data)
	}
	if rf, ok := ret.Get(0).(func(context.Context, io.Reader) string); ok {
		r0 = rf(ctx, data)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, io.Reader) error); ok {
		r1 = rf(ctx, data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewPlugin creates a new instance of Plugin. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPlugin(t interface {
	mock.TestingT
	Cleanup(func())
}) *Plugin {
	mock := &Plugin{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
