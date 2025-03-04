// Code generated by mockery v2.53.0. DO NOT EDIT.

package eventmocks

import (
	context "context"

	blockchain "github.com/hyperledger/firefly/pkg/blockchain"

	core "github.com/hyperledger/firefly/pkg/core"

	dataexchange "github.com/hyperledger/firefly/pkg/dataexchange"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	pkgevents "github.com/hyperledger/firefly/pkg/events"

	sharedstorage "github.com/hyperledger/firefly/pkg/sharedstorage"

	system "github.com/hyperledger/firefly/internal/events/system"

	tokens "github.com/hyperledger/firefly/pkg/tokens"
)

// EventManager is an autogenerated mock type for the EventManager type
type EventManager struct {
	mock.Mock
}

// AddSystemEventListener provides a mock function with given fields: ns, el
func (_m *EventManager) AddSystemEventListener(ns string, el system.EventListener) error {
	ret := _m.Called(ns, el)

	if len(ret) == 0 {
		panic("no return value specified for AddSystemEventListener")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, system.EventListener) error); ok {
		r0 = rf(ns, el)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BlockchainEventBatch provides a mock function with given fields: batch
func (_m *EventManager) BlockchainEventBatch(batch []*blockchain.EventToDispatch) error {
	ret := _m.Called(batch)

	if len(ret) == 0 {
		panic("no return value specified for BlockchainEventBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func([]*blockchain.EventToDispatch) error); ok {
		r0 = rf(batch)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateUpdateDurableSubscription provides a mock function with given fields: ctx, subDef, mustNew
func (_m *EventManager) CreateUpdateDurableSubscription(ctx context.Context, subDef *core.Subscription, mustNew bool) error {
	ret := _m.Called(ctx, subDef, mustNew)

	if len(ret) == 0 {
		panic("no return value specified for CreateUpdateDurableSubscription")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Subscription, bool) error); ok {
		r0 = rf(ctx, subDef, mustNew)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DXEvent provides a mock function with given fields: plugin, event
func (_m *EventManager) DXEvent(plugin dataexchange.Plugin, event dataexchange.DXEvent) error {
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

// DeleteDurableSubscription provides a mock function with given fields: ctx, subDef
func (_m *EventManager) DeleteDurableSubscription(ctx context.Context, subDef *core.Subscription) error {
	ret := _m.Called(ctx, subDef)

	if len(ret) == 0 {
		panic("no return value specified for DeleteDurableSubscription")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Subscription) error); ok {
		r0 = rf(ctx, subDef)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeletedSubscriptions provides a mock function with no fields
func (_m *EventManager) DeletedSubscriptions() chan<- *fftypes.UUID {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for DeletedSubscriptions")
	}

	var r0 chan<- *fftypes.UUID
	if rf, ok := ret.Get(0).(func() chan<- *fftypes.UUID); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(chan<- *fftypes.UUID)
		}
	}

	return r0
}

// EnrichEvent provides a mock function with given fields: ctx, event
func (_m *EventManager) EnrichEvent(ctx context.Context, event *core.Event) (*core.EnrichedEvent, error) {
	ret := _m.Called(ctx, event)

	if len(ret) == 0 {
		panic("no return value specified for EnrichEvent")
	}

	var r0 *core.EnrichedEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Event) (*core.EnrichedEvent, error)); ok {
		return rf(ctx, event)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.Event) *core.EnrichedEvent); ok {
		r0 = rf(ctx, event)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.EnrichedEvent)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.Event) error); ok {
		r1 = rf(ctx, event)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EnrichEvents provides a mock function with given fields: ctx, _a1
func (_m *EventManager) EnrichEvents(ctx context.Context, _a1 []*core.Event) ([]*core.EnrichedEvent, error) {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for EnrichEvents")
	}

	var r0 []*core.EnrichedEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []*core.Event) ([]*core.EnrichedEvent, error)); ok {
		return rf(ctx, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []*core.Event) []*core.EnrichedEvent); ok {
		r0 = rf(ctx, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.EnrichedEvent)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []*core.Event) error); ok {
		r1 = rf(ctx, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterHistoricalEventsOnSubscription provides a mock function with given fields: ctx, _a1, sub
func (_m *EventManager) FilterHistoricalEventsOnSubscription(ctx context.Context, _a1 []*core.EnrichedEvent, sub *core.Subscription) ([]*core.EnrichedEvent, error) {
	ret := _m.Called(ctx, _a1, sub)

	if len(ret) == 0 {
		panic("no return value specified for FilterHistoricalEventsOnSubscription")
	}

	var r0 []*core.EnrichedEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []*core.EnrichedEvent, *core.Subscription) ([]*core.EnrichedEvent, error)); ok {
		return rf(ctx, _a1, sub)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []*core.EnrichedEvent, *core.Subscription) []*core.EnrichedEvent); ok {
		r0 = rf(ctx, _a1, sub)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.EnrichedEvent)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []*core.EnrichedEvent, *core.Subscription) error); ok {
		r1 = rf(ctx, _a1, sub)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPlugins provides a mock function with no fields
func (_m *EventManager) GetPlugins() []*core.NamespaceStatusPlugin {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetPlugins")
	}

	var r0 []*core.NamespaceStatusPlugin
	if rf, ok := ret.Get(0).(func() []*core.NamespaceStatusPlugin); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*core.NamespaceStatusPlugin)
		}
	}

	return r0
}

// NewEvents provides a mock function with no fields
func (_m *EventManager) NewEvents() chan<- int64 {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for NewEvents")
	}

	var r0 chan<- int64
	if rf, ok := ret.Get(0).(func() chan<- int64); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(chan<- int64)
		}
	}

	return r0
}

// NewPins provides a mock function with no fields
func (_m *EventManager) NewPins() chan<- int64 {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for NewPins")
	}

	var r0 chan<- int64
	if rf, ok := ret.Get(0).(func() chan<- int64); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(chan<- int64)
		}
	}

	return r0
}

// NewSubscriptions provides a mock function with no fields
func (_m *EventManager) NewSubscriptions() chan<- *fftypes.UUID {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for NewSubscriptions")
	}

	var r0 chan<- *fftypes.UUID
	if rf, ok := ret.Get(0).(func() chan<- *fftypes.UUID); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(chan<- *fftypes.UUID)
		}
	}

	return r0
}

// QueueBatchRewind provides a mock function with given fields: batchID
func (_m *EventManager) QueueBatchRewind(batchID *fftypes.UUID) {
	_m.Called(batchID)
}

// ResolveTransportAndCapabilities provides a mock function with given fields: ctx, transportName
func (_m *EventManager) ResolveTransportAndCapabilities(ctx context.Context, transportName string) (string, *pkgevents.Capabilities, error) {
	ret := _m.Called(ctx, transportName)

	if len(ret) == 0 {
		panic("no return value specified for ResolveTransportAndCapabilities")
	}

	var r0 string
	var r1 *pkgevents.Capabilities
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, *pkgevents.Capabilities, error)); ok {
		return rf(ctx, transportName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, transportName)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) *pkgevents.Capabilities); ok {
		r1 = rf(ctx, transportName)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*pkgevents.Capabilities)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string) error); ok {
		r2 = rf(ctx, transportName)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// SharedStorageBatchDownloaded provides a mock function with given fields: ss, payloadRef, data
func (_m *EventManager) SharedStorageBatchDownloaded(ss sharedstorage.Plugin, payloadRef string, data []byte) (*fftypes.UUID, error) {
	ret := _m.Called(ss, payloadRef, data)

	if len(ret) == 0 {
		panic("no return value specified for SharedStorageBatchDownloaded")
	}

	var r0 *fftypes.UUID
	var r1 error
	if rf, ok := ret.Get(0).(func(sharedstorage.Plugin, string, []byte) (*fftypes.UUID, error)); ok {
		return rf(ss, payloadRef, data)
	}
	if rf, ok := ret.Get(0).(func(sharedstorage.Plugin, string, []byte) *fftypes.UUID); ok {
		r0 = rf(ss, payloadRef, data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.UUID)
		}
	}

	if rf, ok := ret.Get(1).(func(sharedstorage.Plugin, string, []byte) error); ok {
		r1 = rf(ss, payloadRef, data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SharedStorageBlobDownloaded provides a mock function with given fields: ss, hash, size, payloadRef, dataID
func (_m *EventManager) SharedStorageBlobDownloaded(ss sharedstorage.Plugin, hash fftypes.Bytes32, size int64, payloadRef string, dataID *fftypes.UUID) error {
	ret := _m.Called(ss, hash, size, payloadRef, dataID)

	if len(ret) == 0 {
		panic("no return value specified for SharedStorageBlobDownloaded")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(sharedstorage.Plugin, fftypes.Bytes32, int64, string, *fftypes.UUID) error); ok {
		r0 = rf(ss, hash, size, payloadRef, dataID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Start provides a mock function with no fields
func (_m *EventManager) Start() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Start")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SubscriptionUpdates provides a mock function with no fields
func (_m *EventManager) SubscriptionUpdates() chan<- *fftypes.UUID {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for SubscriptionUpdates")
	}

	var r0 chan<- *fftypes.UUID
	if rf, ok := ret.Get(0).(func() chan<- *fftypes.UUID); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(chan<- *fftypes.UUID)
		}
	}

	return r0
}

// TokenPoolCreated provides a mock function with given fields: ctx, ti, pool
func (_m *EventManager) TokenPoolCreated(ctx context.Context, ti tokens.Plugin, pool *tokens.TokenPool) error {
	ret := _m.Called(ctx, ti, pool)

	if len(ret) == 0 {
		panic("no return value specified for TokenPoolCreated")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, tokens.Plugin, *tokens.TokenPool) error); ok {
		r0 = rf(ctx, ti, pool)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokensApproved provides a mock function with given fields: ti, approval
func (_m *EventManager) TokensApproved(ti tokens.Plugin, approval *tokens.TokenApproval) error {
	ret := _m.Called(ti, approval)

	if len(ret) == 0 {
		panic("no return value specified for TokensApproved")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *tokens.TokenApproval) error); ok {
		r0 = rf(ti, approval)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokensTransferred provides a mock function with given fields: ti, transfer
func (_m *EventManager) TokensTransferred(ti tokens.Plugin, transfer *tokens.TokenTransfer) error {
	ret := _m.Called(ti, transfer)

	if len(ret) == 0 {
		panic("no return value specified for TokensTransferred")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *tokens.TokenTransfer) error); ok {
		r0 = rf(ti, transfer)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WaitStop provides a mock function with no fields
func (_m *EventManager) WaitStop() {
	_m.Called()
}

// NewEventManager creates a new instance of EventManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewEventManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *EventManager {
	mock := &EventManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
