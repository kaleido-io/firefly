// Code generated by mockery v2.53.0. DO NOT EDIT.

package definitionsmocks

import (
	context "context"

	core "github.com/hyperledger/firefly/pkg/core"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"
)

// Sender is an autogenerated mock type for the Sender type
type Sender struct {
	mock.Mock
}

// ClaimIdentity provides a mock function with given fields: ctx, def, signingIdentity, parentSigner
func (_m *Sender) ClaimIdentity(ctx context.Context, def *core.IdentityClaim, signingIdentity *core.SignerRef, parentSigner *core.SignerRef) error {
	ret := _m.Called(ctx, def, signingIdentity, parentSigner)

	if len(ret) == 0 {
		panic("no return value specified for ClaimIdentity")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.IdentityClaim, *core.SignerRef, *core.SignerRef) error); ok {
		r0 = rf(ctx, def, signingIdentity, parentSigner)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DefineContractAPI provides a mock function with given fields: ctx, httpServerURL, api, waitConfirm
func (_m *Sender) DefineContractAPI(ctx context.Context, httpServerURL string, api *core.ContractAPI, waitConfirm bool) error {
	ret := _m.Called(ctx, httpServerURL, api, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for DefineContractAPI")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *core.ContractAPI, bool) error); ok {
		r0 = rf(ctx, httpServerURL, api, waitConfirm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DefineDatatype provides a mock function with given fields: ctx, datatype, waitConfirm
func (_m *Sender) DefineDatatype(ctx context.Context, datatype *core.Datatype, waitConfirm bool) error {
	ret := _m.Called(ctx, datatype, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for DefineDatatype")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Datatype, bool) error); ok {
		r0 = rf(ctx, datatype, waitConfirm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DefineFFI provides a mock function with given fields: ctx, ffi, waitConfirm
func (_m *Sender) DefineFFI(ctx context.Context, ffi *fftypes.FFI, waitConfirm bool) error {
	ret := _m.Called(ctx, ffi, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for DefineFFI")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFI, bool) error); ok {
		r0 = rf(ctx, ffi, waitConfirm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DefineTokenPool provides a mock function with given fields: ctx, pool, waitConfirm
func (_m *Sender) DefineTokenPool(ctx context.Context, pool *core.TokenPool, waitConfirm bool) error {
	ret := _m.Called(ctx, pool, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for DefineTokenPool")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPool, bool) error); ok {
		r0 = rf(ctx, pool, waitConfirm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Name provides a mock function with no fields
func (_m *Sender) Name() string {
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

// PublishContractAPI provides a mock function with given fields: ctx, httpServerURL, name, networkName, waitConfirm
func (_m *Sender) PublishContractAPI(ctx context.Context, httpServerURL string, name string, networkName string, waitConfirm bool) (*core.ContractAPI, error) {
	ret := _m.Called(ctx, httpServerURL, name, networkName, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for PublishContractAPI")
	}

	var r0 *core.ContractAPI
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, bool) (*core.ContractAPI, error)); ok {
		return rf(ctx, httpServerURL, name, networkName, waitConfirm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, bool) *core.ContractAPI); ok {
		r0 = rf(ctx, httpServerURL, name, networkName, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.ContractAPI)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, bool) error); ok {
		r1 = rf(ctx, httpServerURL, name, networkName, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PublishFFI provides a mock function with given fields: ctx, name, version, networkName, waitConfirm
func (_m *Sender) PublishFFI(ctx context.Context, name string, version string, networkName string, waitConfirm bool) (*fftypes.FFI, error) {
	ret := _m.Called(ctx, name, version, networkName, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for PublishFFI")
	}

	var r0 *fftypes.FFI
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, bool) (*fftypes.FFI, error)); ok {
		return rf(ctx, name, version, networkName, waitConfirm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, bool) *fftypes.FFI); ok {
		r0 = rf(ctx, name, version, networkName, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.FFI)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, bool) error); ok {
		r1 = rf(ctx, name, version, networkName, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PublishTokenPool provides a mock function with given fields: ctx, poolNameOrID, networkName, waitConfirm
func (_m *Sender) PublishTokenPool(ctx context.Context, poolNameOrID string, networkName string, waitConfirm bool) (*core.TokenPool, error) {
	ret := _m.Called(ctx, poolNameOrID, networkName, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for PublishTokenPool")
	}

	var r0 *core.TokenPool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) (*core.TokenPool, error)); ok {
		return rf(ctx, poolNameOrID, networkName, waitConfirm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) *core.TokenPool); ok {
		r0 = rf(ctx, poolNameOrID, networkName, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenPool)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, bool) error); ok {
		r1 = rf(ctx, poolNameOrID, networkName, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateIdentity provides a mock function with given fields: ctx, identity, def, signingIdentity, waitConfirm
func (_m *Sender) UpdateIdentity(ctx context.Context, identity *core.Identity, def *core.IdentityUpdate, signingIdentity *core.SignerRef, waitConfirm bool) error {
	ret := _m.Called(ctx, identity, def, signingIdentity, waitConfirm)

	if len(ret) == 0 {
		panic("no return value specified for UpdateIdentity")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Identity, *core.IdentityUpdate, *core.SignerRef, bool) error); ok {
		r0 = rf(ctx, identity, def, signingIdentity, waitConfirm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewSender creates a new instance of Sender. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSender(t interface {
	mock.TestingT
	Cleanup(func())
}) *Sender {
	mock := &Sender{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
