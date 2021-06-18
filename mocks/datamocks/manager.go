// Code generated by mockery v1.0.0. DO NOT EDIT.

package datamocks

import (
	context "context"

	fftypes "github.com/hyperledger-labs/firefly/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// CheckDatatype provides a mock function with given fields: ctx, ns, datatype
func (_m *Manager) CheckDatatype(ctx context.Context, ns string, datatype *fftypes.Datatype) error {
	ret := _m.Called(ctx, ns, datatype)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.Datatype) error); ok {
		r0 = rf(ctx, ns, datatype)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CopyBlobPStoDX provides a mock function with given fields: ctx, _a1
func (_m *Manager) CopyBlobPStoDX(ctx context.Context, _a1 *fftypes.Data) (*fftypes.Blob, error) {
	ret := _m.Called(ctx, _a1)

	var r0 *fftypes.Blob
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.Data) *fftypes.Blob); ok {
		r0 = rf(ctx, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Blob)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.Data) error); ok {
		r1 = rf(ctx, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessageData provides a mock function with given fields: ctx, msg, withValue
func (_m *Manager) GetMessageData(ctx context.Context, msg *fftypes.Message, withValue bool) ([]*fftypes.Data, bool, error) {
	ret := _m.Called(ctx, msg, withValue)

	var r0 []*fftypes.Data
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.Message, bool) []*fftypes.Data); ok {
		r0 = rf(ctx, msg, withValue)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Data)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.Message, bool) bool); ok {
		r1 = rf(ctx, msg, withValue)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, *fftypes.Message, bool) error); ok {
		r2 = rf(ctx, msg, withValue)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ResolveInputDataBroadcast provides a mock function with given fields: ctx, ns, inData
func (_m *Manager) ResolveInputDataBroadcast(ctx context.Context, ns string, inData fftypes.InputData) (fftypes.DataRefs, []*fftypes.DataAndBlob, error) {
	ret := _m.Called(ctx, ns, inData)

	var r0 fftypes.DataRefs
	if rf, ok := ret.Get(0).(func(context.Context, string, fftypes.InputData) fftypes.DataRefs); ok {
		r0 = rf(ctx, ns, inData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.DataRefs)
		}
	}

	var r1 []*fftypes.DataAndBlob
	if rf, ok := ret.Get(1).(func(context.Context, string, fftypes.InputData) []*fftypes.DataAndBlob); ok {
		r1 = rf(ctx, ns, inData)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]*fftypes.DataAndBlob)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, fftypes.InputData) error); ok {
		r2 = rf(ctx, ns, inData)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ResolveInputDataPrivate provides a mock function with given fields: ctx, ns, inData
func (_m *Manager) ResolveInputDataPrivate(ctx context.Context, ns string, inData fftypes.InputData) (fftypes.DataRefs, error) {
	ret := _m.Called(ctx, ns, inData)

	var r0 fftypes.DataRefs
	if rf, ok := ret.Get(0).(func(context.Context, string, fftypes.InputData) fftypes.DataRefs); ok {
		r0 = rf(ctx, ns, inData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.DataRefs)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, fftypes.InputData) error); ok {
		r1 = rf(ctx, ns, inData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UploadBLOB provides a mock function with given fields: ctx, ns, inData, blob, autoMeta
func (_m *Manager) UploadBLOB(ctx context.Context, ns string, inData *fftypes.DataRefOrValue, blob *fftypes.Multipart, autoMeta bool) (*fftypes.Data, error) {
	ret := _m.Called(ctx, ns, inData, blob, autoMeta)

	var r0 *fftypes.Data
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.DataRefOrValue, *fftypes.Multipart, bool) *fftypes.Data); ok {
		r0 = rf(ctx, ns, inData, blob, autoMeta)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Data)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.DataRefOrValue, *fftypes.Multipart, bool) error); ok {
		r1 = rf(ctx, ns, inData, blob, autoMeta)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UploadJSON provides a mock function with given fields: ctx, ns, inData
func (_m *Manager) UploadJSON(ctx context.Context, ns string, inData *fftypes.DataRefOrValue) (*fftypes.Data, error) {
	ret := _m.Called(ctx, ns, inData)

	var r0 *fftypes.Data
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.DataRefOrValue) *fftypes.Data); ok {
		r0 = rf(ctx, ns, inData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Data)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.DataRefOrValue) error); ok {
		r1 = rf(ctx, ns, inData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateAll provides a mock function with given fields: ctx, _a1
func (_m *Manager) ValidateAll(ctx context.Context, _a1 []*fftypes.Data) (bool, error) {
	ret := _m.Called(ctx, _a1)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, []*fftypes.Data) bool); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, []*fftypes.Data) error); ok {
		r1 = rf(ctx, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// VerifyNamespaceExists provides a mock function with given fields: ctx, ns
func (_m *Manager) VerifyNamespaceExists(ctx context.Context, ns string) error {
	ret := _m.Called(ctx, ns)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, ns)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
