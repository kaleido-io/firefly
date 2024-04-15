// Code generated by mockery v2.40.1. DO NOT EDIT.

package wsmocks

import (
	context "context"

	wsclient "github.com/hyperledger/firefly-common/pkg/wsclient"
	mock "github.com/stretchr/testify/mock"
)

// WSClient is an autogenerated mock type for the WSClient type
type WSClient struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *WSClient) Close() {
	_m.Called()
}

// Connect provides a mock function with given fields:
func (_m *WSClient) Connect() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Connect")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Receive provides a mock function with given fields:
func (_m *WSClient) Receive() <-chan []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Receive")
	}

	var r0 <-chan []byte
	if rf, ok := ret.Get(0).(func() <-chan []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan []byte)
		}
	}

	return r0
}

// ReceiveExt provides a mock function with given fields:
func (_m *WSClient) ReceiveExt() <-chan *wsclient.WSPayload {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ReceiveExt")
	}

	var r0 <-chan *wsclient.WSPayload
	if rf, ok := ret.Get(0).(func() <-chan *wsclient.WSPayload); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan *wsclient.WSPayload)
		}
	}

	return r0
}

// Send provides a mock function with given fields: ctx, message
func (_m *WSClient) Send(ctx context.Context, message []byte) error {
	ret := _m.Called(ctx, message)

	if len(ret) == 0 {
		panic("no return value specified for Send")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []byte) error); ok {
		r0 = rf(ctx, message)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetHeader provides a mock function with given fields: header, value
func (_m *WSClient) SetHeader(header string, value string) {
	_m.Called(header, value)
}

// SetURL provides a mock function with given fields: url
func (_m *WSClient) SetURL(url string) {
	_m.Called(url)
}

// URL provides a mock function with given fields:
func (_m *WSClient) URL() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for URL")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// NewWSClient creates a new instance of WSClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewWSClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *WSClient {
	mock := &WSClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
