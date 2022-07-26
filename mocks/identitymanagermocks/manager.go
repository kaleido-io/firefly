// Code generated by mockery v1.0.0. DO NOT EDIT.

package identitymanagermocks

import (
	context "context"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"
	core "github.com/hyperledger/firefly/pkg/core"

	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// CachedIdentityLookupByID provides a mock function with given fields: ctx, id
func (_m *Manager) CachedIdentityLookupByID(ctx context.Context, id *fftypes.UUID) (*core.Identity, error) {
	ret := _m.Called(ctx, id)

	var r0 *core.Identity
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID) *core.Identity); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CachedIdentityLookupMustExist provides a mock function with given fields: ctx, did
func (_m *Manager) CachedIdentityLookupMustExist(ctx context.Context, did string) (*core.Identity, bool, error) {
	ret := _m.Called(ctx, did)

	var r0 *core.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string) *core.Identity); ok {
		r0 = rf(ctx, did)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(context.Context, string) bool); ok {
		r1 = rf(ctx, did)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string) error); ok {
		r2 = rf(ctx, did)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// CachedIdentityLookupNilOK provides a mock function with given fields: ctx, did
func (_m *Manager) CachedIdentityLookupNilOK(ctx context.Context, did string) (*core.Identity, bool, error) {
	ret := _m.Called(ctx, did)

	var r0 *core.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string) *core.Identity); ok {
		r0 = rf(ctx, did)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(context.Context, string) bool); ok {
		r1 = rf(ctx, did)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string) error); ok {
		r2 = rf(ctx, did)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// CachedVerifierLookup provides a mock function with given fields: ctx, vType, value
func (_m *Manager) CachedVerifierLookup(ctx context.Context, vType fftypes.FFEnum, value string) (*core.Verifier, error) {
	ret := _m.Called(ctx, vType, value)

	var r0 *core.Verifier
	if rf, ok := ret.Get(0).(func(context.Context, fftypes.FFEnum, string) *core.Verifier); ok {
		r0 = rf(ctx, vType, value)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Verifier)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, fftypes.FFEnum, string) error); ok {
		r1 = rf(ctx, vType, value)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindIdentityForVerifier provides a mock function with given fields: ctx, iTypes, verifier
func (_m *Manager) FindIdentityForVerifier(ctx context.Context, iTypes []fftypes.FFEnum, verifier *core.VerifierRef) (*core.Identity, error) {
	ret := _m.Called(ctx, iTypes, verifier)

	var r0 *core.Identity
	if rf, ok := ret.Get(0).(func(context.Context, []fftypes.FFEnum, *core.VerifierRef) *core.Identity); ok {
		r0 = rf(ctx, iTypes, verifier)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, []fftypes.FFEnum, *core.VerifierRef) error); ok {
		r1 = rf(ctx, iTypes, verifier)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetLocalNode provides a mock function with given fields: ctx
func (_m *Manager) GetLocalNode(ctx context.Context) (*core.Identity, error) {
	ret := _m.Called(ctx)

	var r0 *core.Identity
	if rf, ok := ret.Get(0).(func(context.Context) *core.Identity); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
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

// GetMultipartyRootOrg provides a mock function with given fields: ctx
func (_m *Manager) GetMultipartyRootOrg(ctx context.Context) (*core.Identity, error) {
	ret := _m.Called(ctx)

	var r0 *core.Identity
	if rf, ok := ret.Get(0).(func(context.Context) *core.Identity); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
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

// GetMultipartyRootVerifier provides a mock function with given fields: ctx
func (_m *Manager) GetMultipartyRootVerifier(ctx context.Context) (*core.VerifierRef, error) {
	ret := _m.Called(ctx)

	var r0 *core.VerifierRef
	if rf, ok := ret.Get(0).(func(context.Context) *core.VerifierRef); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.VerifierRef)
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

// NormalizeSigningKey provides a mock function with given fields: ctx, inputKey, keyNormalizationMode
func (_m *Manager) NormalizeSigningKey(ctx context.Context, inputKey string, keyNormalizationMode int) (string, error) {
	ret := _m.Called(ctx, inputKey, keyNormalizationMode)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string, int) string); ok {
		r0 = rf(ctx, inputKey, keyNormalizationMode)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, int) error); ok {
		r1 = rf(ctx, inputKey, keyNormalizationMode)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResolveIdentitySigner provides a mock function with given fields: ctx, _a1
func (_m *Manager) ResolveIdentitySigner(ctx context.Context, _a1 *core.Identity) (*core.SignerRef, error) {
	ret := _m.Called(ctx, _a1)

	var r0 *core.SignerRef
	if rf, ok := ret.Get(0).(func(context.Context, *core.Identity) *core.SignerRef); ok {
		r0 = rf(ctx, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.SignerRef)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.Identity) error); ok {
		r1 = rf(ctx, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResolveInputSigningIdentity provides a mock function with given fields: ctx, signerRef
func (_m *Manager) ResolveInputSigningIdentity(ctx context.Context, signerRef *core.SignerRef) error {
	ret := _m.Called(ctx, signerRef)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.SignerRef) error); ok {
		r0 = rf(ctx, signerRef)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VerifyIdentityChain provides a mock function with given fields: ctx, _a1
func (_m *Manager) VerifyIdentityChain(ctx context.Context, _a1 *core.Identity) (*core.Identity, bool, error) {
	ret := _m.Called(ctx, _a1)

	var r0 *core.Identity
	if rf, ok := ret.Get(0).(func(context.Context, *core.Identity) *core.Identity); ok {
		r0 = rf(ctx, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Identity)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(context.Context, *core.Identity) bool); ok {
		r1 = rf(ctx, _a1)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, *core.Identity) error); ok {
		r2 = rf(ctx, _a1)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}
