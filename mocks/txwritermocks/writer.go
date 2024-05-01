// Code generated by mockery v2.42.0. DO NOT EDIT.

package txwritermocks

import (
	context "context"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"
	core "github.com/hyperledger/firefly/pkg/core"

	mock "github.com/stretchr/testify/mock"
)

// Writer is an autogenerated mock type for the Writer type
type Writer struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *Writer) Close() {
	_m.Called()
}

// Start provides a mock function with given fields:
func (_m *Writer) Start() {
	_m.Called()
}

// WriteTransactionAndOps provides a mock function with given fields: ctx, txType, idempotencyKey, operations
func (_m *Writer) WriteTransactionAndOps(ctx context.Context, txType fftypes.FFEnum, idempotencyKey core.IdempotencyKey, operations ...*core.Operation) (*core.Transaction, error) {
	_va := make([]interface{}, len(operations))
	for _i := range operations {
		_va[_i] = operations[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, txType, idempotencyKey)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for WriteTransactionAndOps")
	}

	var r0 *core.Transaction
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, fftypes.FFEnum, core.IdempotencyKey, ...*core.Operation) (*core.Transaction, error)); ok {
		return rf(ctx, txType, idempotencyKey, operations...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, fftypes.FFEnum, core.IdempotencyKey, ...*core.Operation) *core.Transaction); ok {
		r0 = rf(ctx, txType, idempotencyKey, operations...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.Transaction)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, fftypes.FFEnum, core.IdempotencyKey, ...*core.Operation) error); ok {
		r1 = rf(ctx, txType, idempotencyKey, operations...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewWriter creates a new instance of Writer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewWriter(t interface {
	mock.TestingT
	Cleanup(func())
}) *Writer {
	mock := &Writer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
