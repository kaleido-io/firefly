// Code generated by mockery v2.40.2. DO NOT EDIT.

package dataexchangemocks

import (
	dataexchange "github.com/hyperledger/firefly/pkg/dataexchange"
	mock "github.com/stretchr/testify/mock"
)

// Callbacks is an autogenerated mock type for the Callbacks type
type Callbacks struct {
	mock.Mock
}

// DXConnectEvent provides a mock function with given fields: plugin
func (_m *Callbacks) DXConnectEvent(plugin dataexchange.Plugin) error {
	ret := _m.Called(plugin)

	if len(ret) == 0 {
		panic("no return value specified for DXConnectEvent")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(dataexchange.Plugin) error); ok {
		r0 = rf(plugin)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DXEvent provides a mock function with given fields: plugin, event
func (_m *Callbacks) DXEvent(plugin dataexchange.Plugin, event dataexchange.DXEvent) error {
	ret := _m.Called(plugin, event)

	if len(ret) == 0 {
		panic("no return value specified for DXEvent")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(dataexchange.Plugin, dataexchange.DXEvent) error); ok {
		r0 = rf(plugin, event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewCallbacks creates a new instance of Callbacks. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCallbacks(t interface {
	mock.TestingT
	Cleanup(func())
}) *Callbacks {
	mock := &Callbacks{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
