// Code generated by mockery v1.0.0. DO NOT EDIT.

package tokenmocks

import (
	context "context"

	config "github.com/hyperledger/firefly/internal/config"

	fftypes "github.com/hyperledger/firefly/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	tokens "github.com/hyperledger/firefly/pkg/tokens"
)

// Plugin is an autogenerated mock type for the Plugin type
type Plugin struct {
	mock.Mock
}

// ActivateTokenPool provides a mock function with given fields: ctx, opID, pool, blockchainInfo
func (_m *Plugin) ActivateTokenPool(ctx context.Context, opID *fftypes.UUID, pool *fftypes.TokenPool, blockchainInfo fftypes.JSONObject) (bool, error) {
	ret := _m.Called(ctx, opID, pool, blockchainInfo)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, *fftypes.TokenPool, fftypes.JSONObject) bool); ok {
		r0 = rf(ctx, opID, pool, blockchainInfo)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, *fftypes.TokenPool, fftypes.JSONObject) error); ok {
		r1 = rf(ctx, opID, pool, blockchainInfo)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BurnTokens provides a mock function with given fields: ctx, opID, poolProtocolID, burn
func (_m *Plugin) BurnTokens(ctx context.Context, opID *fftypes.UUID, poolProtocolID string, burn *fftypes.TokenTransfer) error {
	ret := _m.Called(ctx, opID, poolProtocolID, burn)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, string, *fftypes.TokenTransfer) error); ok {
		r0 = rf(ctx, opID, poolProtocolID, burn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Capabilities provides a mock function with given fields:
func (_m *Plugin) Capabilities() *tokens.Capabilities {
	ret := _m.Called()

	var r0 *tokens.Capabilities
	if rf, ok := ret.Get(0).(func() *tokens.Capabilities); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*tokens.Capabilities)
		}
	}

	return r0
}

// CreateTokenPool provides a mock function with given fields: ctx, opID, pool
func (_m *Plugin) CreateTokenPool(ctx context.Context, opID *fftypes.UUID, pool *fftypes.TokenPool) (bool, error) {
	ret := _m.Called(ctx, opID, pool)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, *fftypes.TokenPool) bool); ok {
		r0 = rf(ctx, opID, pool)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID, *fftypes.TokenPool) error); ok {
		r1 = rf(ctx, opID, pool)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Init provides a mock function with given fields: ctx, name, prefix, callbacks
func (_m *Plugin) Init(ctx context.Context, name string, prefix config.Prefix, callbacks tokens.Callbacks) error {
	ret := _m.Called(ctx, name, prefix, callbacks)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, config.Prefix, tokens.Callbacks) error); ok {
		r0 = rf(ctx, name, prefix, callbacks)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InitPrefix provides a mock function with given fields: prefix
func (_m *Plugin) InitPrefix(prefix config.PrefixArray) {
	_m.Called(prefix)
}

// MintTokens provides a mock function with given fields: ctx, opID, poolProtocolID, mint
func (_m *Plugin) MintTokens(ctx context.Context, opID *fftypes.UUID, poolProtocolID string, mint *fftypes.TokenTransfer) error {
	ret := _m.Called(ctx, opID, poolProtocolID, mint)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, string, *fftypes.TokenTransfer) error); ok {
		r0 = rf(ctx, opID, poolProtocolID, mint)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// TokensApproval provides a mock function with given fields: ctx, opID, poolProtocolID, approval
func (_m *Plugin) TokensApproval(ctx context.Context, opID *fftypes.UUID, poolProtocolID string, approval *fftypes.TokenApproval) error {
	ret := _m.Called(ctx, opID, poolProtocolID, approval)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, string, *fftypes.TokenApproval) error); ok {
		r0 = rf(ctx, opID, poolProtocolID, approval)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TransferTokens provides a mock function with given fields: ctx, opID, poolProtocolID, transfer
func (_m *Plugin) TransferTokens(ctx context.Context, opID *fftypes.UUID, poolProtocolID string, transfer *fftypes.TokenTransfer) error {
	ret := _m.Called(ctx, opID, poolProtocolID, transfer)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID, string, *fftypes.TokenTransfer) error); ok {
		r0 = rf(ctx, opID, poolProtocolID, transfer)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
