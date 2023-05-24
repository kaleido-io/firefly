// Code generated by mockery v2.26.1. DO NOT EDIT.

package dataexchangemocks

import (
	dataexchange "github.com/hyperledger/firefly/pkg/dataexchange"
	mock "github.com/stretchr/testify/mock"
)

// DXEvent is an autogenerated mock type for the DXEvent type
type DXEvent struct {
	mock.Mock
}

// Ack provides a mock function with given fields:
func (_m *DXEvent) Ack() {
	_m.Called()
}

// AckWithManifest provides a mock function with given fields: manifest
func (_m *DXEvent) AckWithManifest(manifest string) {
	_m.Called(manifest)
}

// EventID provides a mock function with given fields:
func (_m *DXEvent) EventID() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MessageReceived provides a mock function with given fields:
func (_m *DXEvent) MessageReceived() *dataexchange.MessageReceived {
	ret := _m.Called()

	var r0 *dataexchange.MessageReceived
	if rf, ok := ret.Get(0).(func() *dataexchange.MessageReceived); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dataexchange.MessageReceived)
		}
	}

	return r0
}

// PrivateBlobReceived provides a mock function with given fields:
func (_m *DXEvent) PrivateBlobReceived() *dataexchange.PrivateBlobReceived {
	ret := _m.Called()

	var r0 *dataexchange.PrivateBlobReceived
	if rf, ok := ret.Get(0).(func() *dataexchange.PrivateBlobReceived); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dataexchange.PrivateBlobReceived)
		}
	}

	return r0
}

// Type provides a mock function with given fields:
func (_m *DXEvent) Type() dataexchange.DXEventType {
	ret := _m.Called()

	var r0 dataexchange.DXEventType
	if rf, ok := ret.Get(0).(func() dataexchange.DXEventType); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(dataexchange.DXEventType)
	}

	return r0
}

type mockConstructorTestingTNewDXEvent interface {
	mock.TestingT
	Cleanup(func())
}

// NewDXEvent creates a new instance of DXEvent. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewDXEvent(t mockConstructorTestingTNewDXEvent) *DXEvent {
	mock := &DXEvent{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
