// Code generated by mockery v1.0.0. DO NOT EDIT.

package tokenmocks

import (
	fftypes "github.com/hyperledger/firefly/pkg/fftypes"
	mock "github.com/stretchr/testify/mock"

	tokens "github.com/hyperledger/firefly/pkg/tokens"
)

// Callbacks is an autogenerated mock type for the Callbacks type
type Callbacks struct {
	mock.Mock
}

// TokenOpUpdate provides a mock function with given fields: plugin, operationID, txState, errorMessage, opOutput
func (_m *Callbacks) TokenOpUpdate(plugin tokens.Plugin, operationID *fftypes.UUID, txState fftypes.OpStatus, errorMessage string, opOutput fftypes.JSONObject) error {
	ret := _m.Called(plugin, operationID, txState, errorMessage, opOutput)

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *fftypes.UUID, fftypes.OpStatus, string, fftypes.JSONObject) error); ok {
		r0 = rf(plugin, operationID, txState, errorMessage, opOutput)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenPoolCreated provides a mock function with given fields: plugin, pool
func (_m *Callbacks) TokenPoolCreated(plugin tokens.Plugin, pool *tokens.TokenPool) error {
	ret := _m.Called(plugin, pool)

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *tokens.TokenPool) error); ok {
		r0 = rf(plugin, pool)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokensTransferred provides a mock function with given fields: plugin, transfer
func (_m *Callbacks) TokensTransferred(plugin tokens.Plugin, transfer *tokens.TokenTransfer) error {
	ret := _m.Called(plugin, transfer)

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *tokens.TokenTransfer) error); ok {
		r0 = rf(plugin, transfer)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
