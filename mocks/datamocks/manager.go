// Code generated by mockery v2.14.1. DO NOT EDIT.

package datamocks

import (
	context "context"

	data "github.com/hyperledger/firefly/internal/data"
	core "github.com/hyperledger/firefly/pkg/core"

	ffapi "github.com/hyperledger/firefly-common/pkg/ffapi"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	io "io"

	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// BlobsEnabled provides a mock function with given fields:
func (_m *Manager) BlobsEnabled() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// CheckDatatype provides a mock function with given fields: ctx, datatype
func (_m *Manager) CheckDatatype(ctx context.Context, datatype *core.Datatype) error {
	ret := _m.Called(ctx, datatype)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Datatype) error); ok {
		r0 = rf(ctx, datatype)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DownloadBlob provides a mock function with given fields: ctx, dataID
func (_m *Manager) DownloadBlob(ctx context.Context, dataID string) (*core.Blob, io.ReadCloser, error) {
	ret := _m.Called(ctx, dataID)

	var r0 *core.Blob
	if rf, ok := ret.Get(0).(func(context.Context, string) *core.Blob); ok {
		r0 = rf(ctx, dataID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Blob)
		}
	}

	var r1 io.ReadCloser
	if rf, ok := ret.Get(1).(func(context.Context, string) io.ReadCloser); ok {
		r1 = rf(ctx, dataID)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(io.ReadCloser)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string) error); ok {
		r2 = rf(ctx, dataID)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetMessageDataCached provides a mock function with given fields: ctx, msg, options
func (_m *Manager) GetMessageDataCached(ctx context.Context, msg *core.Message, options ...data.CacheReadOption) (core.DataArray, bool, error) {
	_va := make([]interface{}, len(options))
	for _i := range options {
		_va[_i] = options[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, msg)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 core.DataArray
	if rf, ok := ret.Get(0).(func(context.Context, *core.Message, ...data.CacheReadOption) core.DataArray); ok {
		r0 = rf(ctx, msg, options...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(core.DataArray)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(context.Context, *core.Message, ...data.CacheReadOption) bool); ok {
		r1 = rf(ctx, msg, options...)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, *core.Message, ...data.CacheReadOption) error); ok {
		r2 = rf(ctx, msg, options...)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetMessageWithDataCached provides a mock function with given fields: ctx, msgID, options
func (_m *Manager) GetMessageWithDataCached(ctx context.Context, msgID *fftypes.UUID, options ...data.CacheReadOption) (*core.Message, core.DataArray, bool, error) {
	_va := make([]interface{}, len(options))
	for _i := range options {
		_va[_i] = options[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, msgID)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *core.Message
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, ...data.CacheReadOption) *core.Message); ok {
		r0 = rf(ctx, msgID, options...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Message)
		}
	}

	var r1 core.DataArray
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, ...data.CacheReadOption) core.DataArray); ok {
		r1 = rf(ctx, msgID, options...)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(core.DataArray)
		}
	}

	var r2 bool
	if rf, ok := ret.Get(2).(func(context.Context, *fftypes.UUID, ...data.CacheReadOption) bool); ok {
		r2 = rf(ctx, msgID, options...)
	} else {
		r2 = ret.Get(2).(bool)
	}

	var r3 error
	if rf, ok := ret.Get(3).(func(context.Context, *fftypes.UUID, ...data.CacheReadOption) error); ok {
		r3 = rf(ctx, msgID, options...)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// HydrateBatch provides a mock function with given fields: ctx, persistedBatch
func (_m *Manager) HydrateBatch(ctx context.Context, persistedBatch *core.BatchPersisted) (*core.Batch, error) {
	ret := _m.Called(ctx, persistedBatch)

	var r0 *core.Batch
	if rf, ok := ret.Get(0).(func(context.Context, *core.BatchPersisted) *core.Batch); ok {
		r0 = rf(ctx, persistedBatch)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Batch)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.BatchPersisted) error); ok {
		r1 = rf(ctx, persistedBatch)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PeekMessageCache provides a mock function with given fields: ctx, id, options
func (_m *Manager) PeekMessageCache(ctx context.Context, id *fftypes.UUID, options ...data.CacheReadOption) (*core.Message, core.DataArray) {
	_va := make([]interface{}, len(options))
	for _i := range options {
		_va[_i] = options[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, id)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *core.Message
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, ...data.CacheReadOption) *core.Message); ok {
		r0 = rf(ctx, id, options...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Message)
		}
	}

	var r1 core.DataArray
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, ...data.CacheReadOption) core.DataArray); ok {
		r1 = rf(ctx, id, options...)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(core.DataArray)
		}
	}

	return r0, r1
}

// ResolveInlineData provides a mock function with given fields: ctx, msg
func (_m *Manager) ResolveInlineData(ctx context.Context, msg *data.NewMessage) error {
	ret := _m.Called(ctx, msg)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *data.NewMessage) error); ok {
		r0 = rf(ctx, msg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Start provides a mock function with given fields:
func (_m *Manager) Start() {
	_m.Called()
}

// UpdateMessageCache provides a mock function with given fields: msg, _a1
func (_m *Manager) UpdateMessageCache(msg *core.Message, _a1 core.DataArray) {
	_m.Called(msg, _a1)
}

// UpdateMessageIfCached provides a mock function with given fields: ctx, msg
func (_m *Manager) UpdateMessageIfCached(ctx context.Context, msg *core.Message) {
	_m.Called(ctx, msg)
}

// UpdateMessageStateIfCached provides a mock function with given fields: ctx, id, state, confirmed
func (_m *Manager) UpdateMessageStateIfCached(ctx context.Context, id *fftypes.UUID, state fftypes.FFEnum, confirmed *fftypes.FFTime) {
	_m.Called(ctx, id, state, confirmed)
}

// UploadBlob provides a mock function with given fields: ctx, inData, blob, autoMeta
func (_m *Manager) UploadBlob(ctx context.Context, inData *core.DataRefOrValue, blob *ffapi.Multipart, autoMeta bool) (*core.Data, error) {
	ret := _m.Called(ctx, inData, blob, autoMeta)

	var r0 *core.Data
	if rf, ok := ret.Get(0).(func(context.Context, *core.DataRefOrValue, *ffapi.Multipart, bool) *core.Data); ok {
		r0 = rf(ctx, inData, blob, autoMeta)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Data)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.DataRefOrValue, *ffapi.Multipart, bool) error); ok {
		r1 = rf(ctx, inData, blob, autoMeta)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UploadJSON provides a mock function with given fields: ctx, inData
func (_m *Manager) UploadJSON(ctx context.Context, inData *core.DataRefOrValue) (*core.Data, error) {
	ret := _m.Called(ctx, inData)

	var r0 *core.Data
	if rf, ok := ret.Get(0).(func(context.Context, *core.DataRefOrValue) *core.Data); ok {
		r0 = rf(ctx, inData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Data)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.DataRefOrValue) error); ok {
		r1 = rf(ctx, inData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateAll provides a mock function with given fields: ctx, _a1
func (_m *Manager) ValidateAll(ctx context.Context, _a1 core.DataArray) (bool, error) {
	ret := _m.Called(ctx, _a1)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, core.DataArray) bool); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, core.DataArray) error); ok {
		r1 = rf(ctx, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WaitStop provides a mock function with given fields:
func (_m *Manager) WaitStop() {
	_m.Called()
}

// WriteNewMessage provides a mock function with given fields: ctx, newMsg
func (_m *Manager) WriteNewMessage(ctx context.Context, newMsg *data.NewMessage) error {
	ret := _m.Called(ctx, newMsg)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *data.NewMessage) error); ok {
		r0 = rf(ctx, newMsg)
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
