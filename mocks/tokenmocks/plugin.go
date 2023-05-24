// Code generated by mockery v2.26.1. DO NOT EDIT.

package tokenmocks

import (
	context "context"

	config "github.com/hyperledger/firefly-common/pkg/config"

	core "github.com/hyperledger/firefly/pkg/core"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	tokens "github.com/hyperledger/firefly/pkg/tokens"
)

// Plugin is an autogenerated mock type for the Plugin type
type Plugin struct {
	mock.Mock
}

// ActivateTokenPool provides a mock function with given fields: ctx, pool
func (_m *Plugin) ActivateTokenPool(ctx context.Context, pool *core.TokenPool) (bool, error) {
	ret := _m.Called(ctx, pool)

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPool) (bool, error)); ok {
		return rf(ctx, pool)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPool) bool); ok {
		r0 = rf(ctx, pool)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.TokenPool) error); ok {
		r1 = rf(ctx, pool)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BurnTokens provides a mock function with given fields: ctx, nsOpID, poolLocator, burn, methods
func (_m *Plugin) BurnTokens(ctx context.Context, nsOpID string, poolLocator string, burn *core.TokenTransfer, methods *fftypes.JSONAny) error {
	ret := _m.Called(ctx, nsOpID, poolLocator, burn, methods)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *core.TokenTransfer, *fftypes.JSONAny) error); ok {
		r0 = rf(ctx, nsOpID, poolLocator, burn, methods)
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

// CheckInterface provides a mock function with given fields: ctx, pool, methods
func (_m *Plugin) CheckInterface(ctx context.Context, pool *core.TokenPool, methods []*fftypes.FFIMethod) (*fftypes.JSONAny, error) {
	ret := _m.Called(ctx, pool, methods)

	var r0 *fftypes.JSONAny
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPool, []*fftypes.FFIMethod) (*fftypes.JSONAny, error)); ok {
		return rf(ctx, pool, methods)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPool, []*fftypes.FFIMethod) *fftypes.JSONAny); ok {
		r0 = rf(ctx, pool, methods)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.JSONAny)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.TokenPool, []*fftypes.FFIMethod) error); ok {
		r1 = rf(ctx, pool, methods)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateTokenPool provides a mock function with given fields: ctx, nsOpID, pool
func (_m *Plugin) CreateTokenPool(ctx context.Context, nsOpID string, pool *core.TokenPool) (bool, error) {
	ret := _m.Called(ctx, nsOpID, pool)

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *core.TokenPool) (bool, error)); ok {
		return rf(ctx, nsOpID, pool)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, *core.TokenPool) bool); ok {
		r0 = rf(ctx, nsOpID, pool)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, *core.TokenPool) error); ok {
		r1 = rf(ctx, nsOpID, pool)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeactivateTokenPool provides a mock function with given fields: ctx, pool
func (_m *Plugin) DeactivateTokenPool(ctx context.Context, pool *core.TokenPool) error {
	ret := _m.Called(ctx, pool)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPool) error); ok {
		r0 = rf(ctx, pool)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Init provides a mock function with given fields: ctx, cancelCtx, name, _a3
func (_m *Plugin) Init(ctx context.Context, cancelCtx context.CancelFunc, name string, _a3 config.Section) error {
	ret := _m.Called(ctx, cancelCtx, name, _a3)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, context.CancelFunc, string, config.Section) error); ok {
		r0 = rf(ctx, cancelCtx, name, _a3)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InitConfig provides a mock function with given fields: _a0
func (_m *Plugin) InitConfig(_a0 config.Section) {
	_m.Called(_a0)
}

// MintTokens provides a mock function with given fields: ctx, nsOpID, poolLocator, mint, methods
func (_m *Plugin) MintTokens(ctx context.Context, nsOpID string, poolLocator string, mint *core.TokenTransfer, methods *fftypes.JSONAny) error {
	ret := _m.Called(ctx, nsOpID, poolLocator, mint, methods)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *core.TokenTransfer, *fftypes.JSONAny) error); ok {
		r0 = rf(ctx, nsOpID, poolLocator, mint, methods)
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

// SetHandler provides a mock function with given fields: namespace, handler
func (_m *Plugin) SetHandler(namespace string, handler tokens.Callbacks) {
	_m.Called(namespace, handler)
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

// TokensApproval provides a mock function with given fields: ctx, nsOpID, poolLocator, approval, methods
func (_m *Plugin) TokensApproval(ctx context.Context, nsOpID string, poolLocator string, approval *core.TokenApproval, methods *fftypes.JSONAny) error {
	ret := _m.Called(ctx, nsOpID, poolLocator, approval, methods)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *core.TokenApproval, *fftypes.JSONAny) error); ok {
		r0 = rf(ctx, nsOpID, poolLocator, approval, methods)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TransferTokens provides a mock function with given fields: ctx, nsOpID, poolLocator, transfer, methods
func (_m *Plugin) TransferTokens(ctx context.Context, nsOpID string, poolLocator string, transfer *core.TokenTransfer, methods *fftypes.JSONAny) error {
	ret := _m.Called(ctx, nsOpID, poolLocator, transfer, methods)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *core.TokenTransfer, *fftypes.JSONAny) error); ok {
		r0 = rf(ctx, nsOpID, poolLocator, transfer, methods)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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
