// Code generated by mockery v1.0.0. DO NOT EDIT.

package databasemocks

import (
	fftypes "github.com/hyperledger-labs/firefly/pkg/fftypes"
	mock "github.com/stretchr/testify/mock"
)

// Callbacks is an autogenerated mock type for the Callbacks type
type Callbacks struct {
	mock.Mock
}

// EventCreated provides a mock function with given fields: sequence
func (_m *Callbacks) EventCreated(sequence int64) {
	_m.Called(sequence)
}

// MessageCreated provides a mock function with given fields: sequence
func (_m *Callbacks) MessageCreated(sequence int64) {
	_m.Called(sequence)
}

// PinCreated provides a mock function with given fields: sequence
func (_m *Callbacks) PinCreated(sequence int64) {
	_m.Called(sequence)
}

// SubscriptionCreated provides a mock function with given fields: id
func (_m *Callbacks) SubscriptionCreated(id *fftypes.UUID) {
	_m.Called(id)
}

// SubscriptionDeleted provides a mock function with given fields: id
func (_m *Callbacks) SubscriptionDeleted(id *fftypes.UUID) {
	_m.Called(id)
}
