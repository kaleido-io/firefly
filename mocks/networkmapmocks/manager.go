// Code generated by mockery v1.0.0. DO NOT EDIT.

package networkmapmocks

import (
	context "context"

	database "github.com/hyperledger/firefly/pkg/database"
	fftypes "github.com/hyperledger/firefly/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	networkmap "github.com/hyperledger/firefly/internal/networkmap"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// GetDIDDocForIndentityByID provides a mock function with given fields: ctx, ns, id
func (_m *Manager) GetDIDDocForIndentityByID(ctx context.Context, ns string, id string) (*networkmap.DIDDocument, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *networkmap.DIDDocument
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *networkmap.DIDDocument); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*networkmap.DIDDocument)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetIdentities provides a mock function with given fields: ctx, ns, filter
func (_m *Manager) GetIdentities(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Identity, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Identity); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Identity)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetIdentityByID provides a mock function with given fields: ctx, ns, id
func (_m *Manager) GetIdentityByID(ctx context.Context, ns string, id string) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Identity); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetIdentityVerifiers provides a mock function with given fields: ctx, ns, id, filter
func (_m *Manager) GetIdentityVerifiers(ctx context.Context, ns string, id string, filter database.AndFilter) ([]*fftypes.Verifier, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, id, filter)

	var r0 []*fftypes.Verifier
	if rf, ok := ret.Get(0).(func(context.Context, string, string, database.AndFilter) []*fftypes.Verifier); ok {
		r0 = rf(ctx, ns, id, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Verifier)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, id, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, id, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetNodeByNameOrID provides a mock function with given fields: ctx, nameOrID
func (_m *Manager) GetNodeByNameOrID(ctx context.Context, nameOrID string) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, nameOrID)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string) *fftypes.Identity); ok {
		r0 = rf(ctx, nameOrID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, nameOrID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNodes provides a mock function with given fields: ctx, filter
func (_m *Manager) GetNodes(ctx context.Context, filter database.AndFilter) ([]*fftypes.Identity, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*fftypes.Identity); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Identity)
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

// GetOrganizationByNameOrID provides a mock function with given fields: ctx, nameOrID
func (_m *Manager) GetOrganizationByNameOrID(ctx context.Context, nameOrID string) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, nameOrID)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string) *fftypes.Identity); ok {
		r0 = rf(ctx, nameOrID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, nameOrID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetOrganizations provides a mock function with given fields: ctx, filter
func (_m *Manager) GetOrganizations(ctx context.Context, filter database.AndFilter) ([]*fftypes.Identity, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*fftypes.Identity); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Identity)
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

// GetVerifierByHash provides a mock function with given fields: ctx, ns, hash
func (_m *Manager) GetVerifierByHash(ctx context.Context, ns string, hash string) (*fftypes.Verifier, error) {
	ret := _m.Called(ctx, ns, hash)

	var r0 *fftypes.Verifier
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Verifier); ok {
		r0 = rf(ctx, ns, hash)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Verifier)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, hash)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetVerifiers provides a mock function with given fields: ctx, ns, filter
func (_m *Manager) GetVerifiers(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Verifier, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Verifier
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Verifier); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Verifier)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// RegisterIdentity provides a mock function with given fields: ctx, ns, dto, waitConfirm
func (_m *Manager) RegisterIdentity(ctx context.Context, ns string, dto *fftypes.IdentityCreateDTO, waitConfirm bool) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, ns, dto, waitConfirm)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.IdentityCreateDTO, bool) *fftypes.Identity); ok {
		r0 = rf(ctx, ns, dto, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.IdentityCreateDTO, bool) error); ok {
		r1 = rf(ctx, ns, dto, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegisterNode provides a mock function with given fields: ctx, waitConfirm
func (_m *Manager) RegisterNode(ctx context.Context, waitConfirm bool) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, waitConfirm)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, bool) *fftypes.Identity); ok {
		r0 = rf(ctx, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, bool) error); ok {
		r1 = rf(ctx, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegisterNodeOrganization provides a mock function with given fields: ctx, waitConfirm
func (_m *Manager) RegisterNodeOrganization(ctx context.Context, waitConfirm bool) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, waitConfirm)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, bool) *fftypes.Identity); ok {
		r0 = rf(ctx, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, bool) error); ok {
		r1 = rf(ctx, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegisterOrganization provides a mock function with given fields: ctx, org, waitConfirm
func (_m *Manager) RegisterOrganization(ctx context.Context, org *fftypes.IdentityCreateDTO, waitConfirm bool) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, org, waitConfirm)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.IdentityCreateDTO, bool) *fftypes.Identity); ok {
		r0 = rf(ctx, org, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.IdentityCreateDTO, bool) error); ok {
		r1 = rf(ctx, org, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateIdentity provides a mock function with given fields: ctx, ns, id, dto, waitConfirm
func (_m *Manager) UpdateIdentity(ctx context.Context, ns string, id string, dto *fftypes.IdentityUpdateDTO, waitConfirm bool) (*fftypes.Identity, error) {
	ret := _m.Called(ctx, ns, id, dto, waitConfirm)

	var r0 *fftypes.Identity
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *fftypes.IdentityUpdateDTO, bool) *fftypes.Identity); ok {
		r0 = rf(ctx, ns, id, dto, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, *fftypes.IdentityUpdateDTO, bool) error); ok {
		r1 = rf(ctx, ns, id, dto, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
