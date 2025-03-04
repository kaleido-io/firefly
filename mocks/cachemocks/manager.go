// Code generated by mockery v2.53.0. DO NOT EDIT.

package cachemocks

import (
	cache "github.com/hyperledger/firefly/internal/cache"
	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// GetCache provides a mock function with given fields: cc
func (_m *Manager) GetCache(cc *cache.CConfig) (cache.CInterface, error) {
	ret := _m.Called(cc)

	if len(ret) == 0 {
		panic("no return value specified for GetCache")
	}

	var r0 cache.CInterface
	var r1 error
	if rf, ok := ret.Get(0).(func(*cache.CConfig) (cache.CInterface, error)); ok {
		return rf(cc)
	}
	if rf, ok := ret.Get(0).(func(*cache.CConfig) cache.CInterface); ok {
		r0 = rf(cc)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(cache.CInterface)
		}
	}

	if rf, ok := ret.Get(1).(func(*cache.CConfig) error); ok {
		r1 = rf(cc)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListCacheNames provides a mock function with given fields: namespace
func (_m *Manager) ListCacheNames(namespace string) []string {
	ret := _m.Called(namespace)

	if len(ret) == 0 {
		panic("no return value specified for ListCacheNames")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(namespace)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// ResetCachesForNamespace provides a mock function with given fields: ns
func (_m *Manager) ResetCachesForNamespace(ns string) {
	_m.Called(ns)
}

// NewManager creates a new instance of Manager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *Manager {
	mock := &Manager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
