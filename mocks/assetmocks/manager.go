// Code generated by mockery v2.14.1. DO NOT EDIT.

package assetmocks

import (
	context "context"

	core "github.com/hyperledger/firefly/pkg/core"
	database "github.com/hyperledger/firefly/pkg/database"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	syncasync "github.com/hyperledger/firefly/internal/syncasync"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// ActivateTokenPool provides a mock function with given fields: ctx, pool
func (_m *Manager) ActivateTokenPool(ctx context.Context, pool *core.TokenPool) error {
	ret := _m.Called(ctx, pool)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPool) error); ok {
		r0 = rf(ctx, pool)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BurnTokens provides a mock function with given fields: ctx, transfer, waitConfirm
func (_m *Manager) BurnTokens(ctx context.Context, transfer *core.TokenTransferInput, waitConfirm bool) (*core.TokenTransfer, error) {
	ret := _m.Called(ctx, transfer, waitConfirm)

	var r0 *core.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenTransferInput, bool) *core.TokenTransfer); ok {
		r0 = rf(ctx, transfer, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenTransfer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.TokenTransferInput, bool) error); ok {
		r1 = rf(ctx, transfer, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateTokenPool provides a mock function with given fields: ctx, pool, waitConfirm
func (_m *Manager) CreateTokenPool(ctx context.Context, pool *core.TokenPoolInput, waitConfirm bool) (*core.TokenPool, error) {
	ret := _m.Called(ctx, pool, waitConfirm)

	var r0 *core.TokenPool
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenPoolInput, bool) *core.TokenPool); ok {
		r0 = rf(ctx, pool, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenPool)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.TokenPoolInput, bool) error); ok {
		r1 = rf(ctx, pool, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTokenAccountPools provides a mock function with given fields: ctx, key, filter
func (_m *Manager) GetTokenAccountPools(ctx context.Context, key string, filter database.AndFilter) ([]*core.TokenAccountPool, *database.FilterResult, error) {
	ret := _m.Called(ctx, key, filter)

	var r0 []*core.TokenAccountPool
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*core.TokenAccountPool); ok {
		r0 = rf(ctx, key, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.TokenAccountPool)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, key, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, database.AndFilter) error); ok {
		r2 = rf(ctx, key, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetTokenAccounts provides a mock function with given fields: ctx, filter
func (_m *Manager) GetTokenAccounts(ctx context.Context, filter database.AndFilter) ([]*core.TokenAccount, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*core.TokenAccount
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*core.TokenAccount); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.TokenAccount)
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

// GetTokenApprovals provides a mock function with given fields: ctx, filter
func (_m *Manager) GetTokenApprovals(ctx context.Context, filter database.AndFilter) ([]*core.TokenApproval, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*core.TokenApproval
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*core.TokenApproval); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.TokenApproval)
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

// GetTokenBalances provides a mock function with given fields: ctx, filter
func (_m *Manager) GetTokenBalances(ctx context.Context, filter database.AndFilter) ([]*core.TokenBalance, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*core.TokenBalance
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*core.TokenBalance); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.TokenBalance)
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

// GetTokenConnectors provides a mock function with given fields: ctx
func (_m *Manager) GetTokenConnectors(ctx context.Context) []*core.TokenConnector {
	ret := _m.Called(ctx)

	var r0 []*core.TokenConnector
	if rf, ok := ret.Get(0).(func(context.Context) []*core.TokenConnector); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.TokenConnector)
		}
	}

	return r0
}

// GetTokenPool provides a mock function with given fields: ctx, connector, poolName
func (_m *Manager) GetTokenPool(ctx context.Context, connector string, poolName string) (*core.TokenPool, error) {
	ret := _m.Called(ctx, connector, poolName)

	var r0 *core.TokenPool
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *core.TokenPool); ok {
		r0 = rf(ctx, connector, poolName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenPool)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, connector, poolName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTokenPoolByNameOrID provides a mock function with given fields: ctx, poolNameOrID
func (_m *Manager) GetTokenPoolByNameOrID(ctx context.Context, poolNameOrID string) (*core.TokenPool, error) {
	ret := _m.Called(ctx, poolNameOrID)

	var r0 *core.TokenPool
	if rf, ok := ret.Get(0).(func(context.Context, string) *core.TokenPool); ok {
		r0 = rf(ctx, poolNameOrID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenPool)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, poolNameOrID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTokenPools provides a mock function with given fields: ctx, filter
func (_m *Manager) GetTokenPools(ctx context.Context, filter database.AndFilter) ([]*core.TokenPool, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*core.TokenPool
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*core.TokenPool); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.TokenPool)
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

// GetTokenTransferByID provides a mock function with given fields: ctx, id
func (_m *Manager) GetTokenTransferByID(ctx context.Context, id string) (*core.TokenTransfer, error) {
	ret := _m.Called(ctx, id)

	var r0 *core.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, string) *core.TokenTransfer); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenTransfer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTokenTransfers provides a mock function with given fields: ctx, filter
func (_m *Manager) GetTokenTransfers(ctx context.Context, filter database.AndFilter) ([]*core.TokenTransfer, *database.FilterResult, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*core.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*core.TokenTransfer); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.TokenTransfer)
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

// MintTokens provides a mock function with given fields: ctx, transfer, waitConfirm
func (_m *Manager) MintTokens(ctx context.Context, transfer *core.TokenTransferInput, waitConfirm bool) (*core.TokenTransfer, error) {
	ret := _m.Called(ctx, transfer, waitConfirm)

	var r0 *core.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenTransferInput, bool) *core.TokenTransfer); ok {
		r0 = rf(ctx, transfer, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenTransfer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.TokenTransferInput, bool) error); ok {
		r1 = rf(ctx, transfer, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Name provides a mock function with given fields:
func (_m *Manager) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// NewApproval provides a mock function with given fields: approve
func (_m *Manager) NewApproval(approve *core.TokenApprovalInput) syncasync.Sender {
	ret := _m.Called(approve)

	var r0 syncasync.Sender
	if rf, ok := ret.Get(0).(func(*core.TokenApprovalInput) syncasync.Sender); ok {
		r0 = rf(approve)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(syncasync.Sender)
		}
	}

	return r0
}

// NewTransfer provides a mock function with given fields: transfer
func (_m *Manager) NewTransfer(transfer *core.TokenTransferInput) syncasync.Sender {
	ret := _m.Called(transfer)

	var r0 syncasync.Sender
	if rf, ok := ret.Get(0).(func(*core.TokenTransferInput) syncasync.Sender); ok {
		r0 = rf(transfer)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(syncasync.Sender)
		}
	}

	return r0
}

// PrepareOperation provides a mock function with given fields: ctx, op
func (_m *Manager) PrepareOperation(ctx context.Context, op *core.Operation) (*core.PreparedOperation, error) {
	ret := _m.Called(ctx, op)

	var r0 *core.PreparedOperation
	if rf, ok := ret.Get(0).(func(context.Context, *core.Operation) *core.PreparedOperation); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.PreparedOperation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.Operation) error); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RunOperation provides a mock function with given fields: ctx, op
func (_m *Manager) RunOperation(ctx context.Context, op *core.PreparedOperation) (fftypes.JSONObject, bool, error) {
	ret := _m.Called(ctx, op)

	var r0 fftypes.JSONObject
	if rf, ok := ret.Get(0).(func(context.Context, *core.PreparedOperation) fftypes.JSONObject); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.JSONObject)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(context.Context, *core.PreparedOperation) bool); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, *core.PreparedOperation) error); ok {
		r2 = rf(ctx, op)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// TokenApproval provides a mock function with given fields: ctx, approval, waitConfirm
func (_m *Manager) TokenApproval(ctx context.Context, approval *core.TokenApprovalInput, waitConfirm bool) (*core.TokenApproval, error) {
	ret := _m.Called(ctx, approval, waitConfirm)

	var r0 *core.TokenApproval
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenApprovalInput, bool) *core.TokenApproval); ok {
		r0 = rf(ctx, approval, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenApproval)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.TokenApprovalInput, bool) error); ok {
		r1 = rf(ctx, approval, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TransferTokens provides a mock function with given fields: ctx, transfer, waitConfirm
func (_m *Manager) TransferTokens(ctx context.Context, transfer *core.TokenTransferInput, waitConfirm bool) (*core.TokenTransfer, error) {
	ret := _m.Called(ctx, transfer, waitConfirm)

	var r0 *core.TokenTransfer
	if rf, ok := ret.Get(0).(func(context.Context, *core.TokenTransferInput, bool) *core.TokenTransfer); ok {
		r0 = rf(ctx, transfer, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.TokenTransfer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.TokenTransferInput, bool) error); ok {
		r1 = rf(ctx, transfer, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
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
