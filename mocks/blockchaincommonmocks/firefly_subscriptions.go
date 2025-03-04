// Code generated by mockery v2.53.0. DO NOT EDIT.

package blockchaincommonmocks

import (
	context "context"

	common "github.com/hyperledger/firefly/internal/blockchain/common"

	core "github.com/hyperledger/firefly/pkg/core"

	mock "github.com/stretchr/testify/mock"
)

// FireflySubscriptions is an autogenerated mock type for the FireflySubscriptions type
type FireflySubscriptions struct {
	mock.Mock
}

// AddSubscription provides a mock function with given fields: ctx, namespace, version, subID, extra
func (_m *FireflySubscriptions) AddSubscription(ctx context.Context, namespace *core.Namespace, version int, subID string, extra interface{}) {
	_m.Called(ctx, namespace, version, subID, extra)
}

// GetSubscription provides a mock function with given fields: subID
func (_m *FireflySubscriptions) GetSubscription(subID string) *common.SubscriptionInfo {
	ret := _m.Called(subID)

	if len(ret) == 0 {
		panic("no return value specified for GetSubscription")
	}

	var r0 *common.SubscriptionInfo
	if rf, ok := ret.Get(0).(func(string) *common.SubscriptionInfo); ok {
		r0 = rf(subID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*common.SubscriptionInfo)
		}
	}

	return r0
}

// RemoveSubscription provides a mock function with given fields: ctx, subID
func (_m *FireflySubscriptions) RemoveSubscription(ctx context.Context, subID string) {
	_m.Called(ctx, subID)
}

// NewFireflySubscriptions creates a new instance of FireflySubscriptions. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFireflySubscriptions(t interface {
	mock.TestingT
	Cleanup(func())
}) *FireflySubscriptions {
	mock := &FireflySubscriptions{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
