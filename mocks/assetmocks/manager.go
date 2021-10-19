// Code generated by mockery v1.0.0. DO NOT EDIT.

package assetmocks

import (
	context "context"

	database "github.com/hyperledger/firefly/pkg/database"
	fftypes "github.com/hyperledger/firefly/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	sysmessaging "github.com/hyperledger/firefly/internal/sysmessaging"

	tokens "github.com/hyperledger/firefly/pkg/tokens"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// BurnTokens provides a mock function with given fields: ctx, ns, typeName, poolName, transfer, waitConfirm
func (_m *Manager) BurnTokens(ctx context.Context, ns string, typeName string, poolName string, transfer *fftypes.TokenTransferInput, waitConfirm bool) (*fftypes.TokenTransfer, error) {
	ret := _m.Called(ctx, ns, typeName, poolName, transfer, waitConfirm)

	var r0 *fftypes.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *fftypes.TokenTransferInput, bool) *fftypes.TokenTransfer); ok {
		r0 = rf(ctx, ns, typeName, poolName, transfer, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.TokenTransfer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, *fftypes.TokenTransferInput, bool) error); ok {
		r1 = rf(ctx, ns, typeName, poolName, transfer, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateTokenPool provides a mock function with given fields: ctx, ns, typeName, pool, waitConfirm
func (_m *Manager) CreateTokenPool(ctx context.Context, ns string, typeName string, pool *fftypes.TokenPool, waitConfirm bool) (*fftypes.TokenPool, error) {
	ret := _m.Called(ctx, ns, typeName, pool, waitConfirm)

	var r0 *fftypes.TokenPool
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *fftypes.TokenPool, bool) *fftypes.TokenPool); ok {
		r0 = rf(ctx, ns, typeName, pool, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.TokenPool)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, *fftypes.TokenPool, bool) error); ok {
		r1 = rf(ctx, ns, typeName, pool, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTokenAccounts provides a mock function with given fields: ctx, ns, typeName, poolName, filter
func (_m *Manager) GetTokenAccounts(ctx context.Context, ns string, typeName string, poolName string, filter database.AndFilter) ([]*fftypes.TokenAccount, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, typeName, poolName, filter)

	var r0 []*fftypes.TokenAccount
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, database.AndFilter) []*fftypes.TokenAccount); ok {
		r0 = rf(ctx, ns, typeName, poolName, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.TokenAccount)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, typeName, poolName, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, string, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, typeName, poolName, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetTokenConnectors provides a mock function with given fields: ctx, ns
func (_m *Manager) GetTokenConnectors(ctx context.Context, ns string) ([]*fftypes.TokenConnector, error) {
	ret := _m.Called(ctx, ns)

	var r0 []*fftypes.TokenConnector
	if rf, ok := ret.Get(0).(func(context.Context, string) []*fftypes.TokenConnector); ok {
		r0 = rf(ctx, ns)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.TokenConnector)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, ns)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTokenPool provides a mock function with given fields: ctx, ns, typeName, poolName
func (_m *Manager) GetTokenPool(ctx context.Context, ns string, typeName string, poolName string) (*fftypes.TokenPool, error) {
	ret := _m.Called(ctx, ns, typeName, poolName)

	var r0 *fftypes.TokenPool
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) *fftypes.TokenPool); ok {
		r0 = rf(ctx, ns, typeName, poolName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.TokenPool)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, ns, typeName, poolName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTokenPools provides a mock function with given fields: ctx, ns, typeName, filter
func (_m *Manager) GetTokenPools(ctx context.Context, ns string, typeName string, filter database.AndFilter) ([]*fftypes.TokenPool, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, typeName, filter)

	var r0 []*fftypes.TokenPool
	if rf, ok := ret.Get(0).(func(context.Context, string, string, database.AndFilter) []*fftypes.TokenPool); ok {
		r0 = rf(ctx, ns, typeName, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.TokenPool)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, typeName, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, typeName, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetTokenTransfers provides a mock function with given fields: ctx, ns, typeName, poolName, filter
func (_m *Manager) GetTokenTransfers(ctx context.Context, ns string, typeName string, poolName string, filter database.AndFilter) ([]*fftypes.TokenTransfer, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, typeName, poolName, filter)

	var r0 []*fftypes.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, database.AndFilter) []*fftypes.TokenTransfer); ok {
		r0 = rf(ctx, ns, typeName, poolName, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.TokenTransfer)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, typeName, poolName, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, string, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, typeName, poolName, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MintTokens provides a mock function with given fields: ctx, ns, typeName, poolName, transfer, waitConfirm
func (_m *Manager) MintTokens(ctx context.Context, ns string, typeName string, poolName string, transfer *fftypes.TokenTransferInput, waitConfirm bool) (*fftypes.TokenTransfer, error) {
	ret := _m.Called(ctx, ns, typeName, poolName, transfer, waitConfirm)

	var r0 *fftypes.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *fftypes.TokenTransferInput, bool) *fftypes.TokenTransfer); ok {
		r0 = rf(ctx, ns, typeName, poolName, transfer, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.TokenTransfer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, *fftypes.TokenTransferInput, bool) error); ok {
		r1 = rf(ctx, ns, typeName, poolName, transfer, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewTransfer provides a mock function with given fields: ns, typeName, poolName, transfer
func (_m *Manager) NewTransfer(ns string, typeName string, poolName string, transfer *fftypes.TokenTransferInput) sysmessaging.MessageSender {
	ret := _m.Called(ns, typeName, poolName, transfer)

	var r0 sysmessaging.MessageSender
	if rf, ok := ret.Get(0).(func(string, string, string, *fftypes.TokenTransferInput) sysmessaging.MessageSender); ok {
		r0 = rf(ns, typeName, poolName, transfer)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(sysmessaging.MessageSender)
		}
	}

	return r0
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

// TokenPoolCreated provides a mock function with given fields: tk, pool, protocolTxID, additionalInfo
func (_m *Manager) TokenPoolCreated(tk tokens.Plugin, pool *fftypes.TokenPool, protocolTxID string, additionalInfo fftypes.JSONObject) error {
	ret := _m.Called(tk, pool, protocolTxID, additionalInfo)

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *fftypes.TokenPool, string, fftypes.JSONObject) error); ok {
		r0 = rf(tk, pool, protocolTxID, additionalInfo)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TransferTokens provides a mock function with given fields: ctx, ns, typeName, poolName, transfer, waitConfirm
func (_m *Manager) TransferTokens(ctx context.Context, ns string, typeName string, poolName string, transfer *fftypes.TokenTransferInput, waitConfirm bool) (*fftypes.TokenTransfer, error) {
	ret := _m.Called(ctx, ns, typeName, poolName, transfer, waitConfirm)

	var r0 *fftypes.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *fftypes.TokenTransferInput, bool) *fftypes.TokenTransfer); ok {
		r0 = rf(ctx, ns, typeName, poolName, transfer, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.TokenTransfer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, *fftypes.TokenTransferInput, bool) error); ok {
		r1 = rf(ctx, ns, typeName, poolName, transfer, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateTokenPoolTx provides a mock function with given fields: ctx, pool, protocolTxID
func (_m *Manager) ValidateTokenPoolTx(ctx context.Context, pool *fftypes.TokenPool, protocolTxID string) error {
	ret := _m.Called(ctx, pool, protocolTxID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.TokenPool, string) error); ok {
		r0 = rf(ctx, pool, protocolTxID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WaitStop provides a mock function with given fields:
func (_m *Manager) WaitStop() {
	_m.Called()
}
