// Code generated by mockery v1.0.0. DO NOT EDIT.

package batchpinmocks

import (
	context "context"

	fftypes "github.com/hyperledger/firefly/pkg/fftypes"
	mock "github.com/stretchr/testify/mock"
)

// Submitter is an autogenerated mock type for the Submitter type
type Submitter struct {
	mock.Mock
}

// Name provides a mock function with given fields:
func (_m *Submitter) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// PrepareOperation provides a mock function with given fields: ctx, op
func (_m *Submitter) PrepareOperation(ctx context.Context, op *fftypes.Operation) (*fftypes.PreparedOperation, error) {
	ret := _m.Called(ctx, op)

	var r0 *fftypes.PreparedOperation
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.Operation) *fftypes.PreparedOperation); ok {
		r0 = rf(ctx, op)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.PreparedOperation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.Operation) error); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RunOperation provides a mock function with given fields: ctx, op
func (_m *Submitter) RunOperation(ctx context.Context, op *fftypes.PreparedOperation) (bool, error) {
	ret := _m.Called(ctx, op)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.PreparedOperation) bool); ok {
		r0 = rf(ctx, op)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.PreparedOperation) error); ok {
		r1 = rf(ctx, op)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SubmitPinnedBatch provides a mock function with given fields: ctx, batch, contexts
func (_m *Submitter) SubmitPinnedBatch(ctx context.Context, batch *fftypes.BatchPersisted, contexts []*fftypes.Bytes32) error {
	ret := _m.Called(ctx, batch, contexts)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.BatchPersisted, []*fftypes.Bytes32) error); ok {
		r0 = rf(ctx, batch, contexts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
