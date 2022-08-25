// Code generated by mockery v1.0.0. DO NOT EDIT.

package eventmocks

import (
	context "context"

	blockchain "github.com/hyperledger/firefly/pkg/blockchain"

	core "github.com/hyperledger/firefly/pkg/core"

	dataexchange "github.com/hyperledger/firefly/pkg/dataexchange"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

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

	var r0 error
	if rf, ok := ret.Get(0).(func(string, system.EventListener) error); ok {
		r0 = rf(ns, el)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BatchPinComplete provides a mock function with given fields: namespace, batch, signingKey
func (_m *EventManager) BatchPinComplete(namespace string, batch *blockchain.BatchPin, signingKey *core.VerifierRef) error {
	ret := _m.Called(namespace, batch, signingKey)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *blockchain.BatchPin, *core.VerifierRef) error); ok {
		r0 = rf(namespace, batch, signingKey)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BlockchainEvent provides a mock function with given fields: event
func (_m *EventManager) BlockchainEvent(event *blockchain.EventWithSubscription) error {
	ret := _m.Called(event)

	var r0 error
	if rf, ok := ret.Get(0).(func(*blockchain.EventWithSubscription) error); ok {
		r0 = rf(event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BlockchainNetworkAction provides a mock function with given fields: action, location, event, signingKey
func (_m *EventManager) BlockchainNetworkAction(action string, location *fftypes.JSONAny, event *blockchain.Event, signingKey *core.VerifierRef) error {
	ret := _m.Called(action, location, event, signingKey)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *fftypes.JSONAny, *blockchain.Event, *core.VerifierRef) error); ok {
		r0 = rf(action, location, event, signingKey)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateUpdateDurableSubscription provides a mock function with given fields: ctx, subDef, mustNew
func (_m *EventManager) CreateUpdateDurableSubscription(ctx context.Context, subDef *core.Subscription, mustNew bool) error {
	ret := _m.Called(ctx, subDef, mustNew)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Subscription, bool) error); ok {
		r0 = rf(ctx, subDef, mustNew)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DXEvent provides a mock function with given fields: plugin, event
func (_m *EventManager) DXEvent(plugin dataexchange.Plugin, event dataexchange.DXEvent) {
	_m.Called(plugin, event)
}

// DeleteDurableSubscription provides a mock function with given fields: ctx, subDef
func (_m *EventManager) DeleteDurableSubscription(ctx context.Context, subDef *core.Subscription) error {
	ret := _m.Called(ctx, subDef)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Subscription) error); ok {
		r0 = rf(ctx, subDef)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeletedSubscriptions provides a mock function with given fields:
func (_m *EventManager) DeletedSubscriptions() chan<- *fftypes.UUID {
	ret := _m.Called()

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

	var r0 *core.EnrichedEvent
	if rf, ok := ret.Get(0).(func(context.Context, *core.Event) *core.EnrichedEvent); ok {
		r0 = rf(ctx, event)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*core.EnrichedEvent)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.Event) error); ok {
		r1 = rf(ctx, event)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPlugins provides a mock function with given fields:
func (_m *EventManager) GetPlugins() []*core.NamespaceStatusPlugin {
	ret := _m.Called()

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

// NewEvents provides a mock function with given fields:
func (_m *EventManager) NewEvents() chan<- int64 {
	ret := _m.Called()

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

// NewPins provides a mock function with given fields:
func (_m *EventManager) NewPins() chan<- int64 {
	ret := _m.Called()

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

// NewSubscriptions provides a mock function with given fields:
func (_m *EventManager) NewSubscriptions() chan<- *fftypes.UUID {
	ret := _m.Called()

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

// SharedStorageBatchDownloaded provides a mock function with given fields: ss, payloadRef, data
func (_m *EventManager) SharedStorageBatchDownloaded(ss sharedstorage.Plugin, payloadRef string, data []byte) (*fftypes.UUID, error) {
	ret := _m.Called(ss, payloadRef, data)

	var r0 *fftypes.UUID
	if rf, ok := ret.Get(0).(func(sharedstorage.Plugin, string, []byte) *fftypes.UUID); ok {
		r0 = rf(ss, payloadRef, data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.UUID)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(sharedstorage.Plugin, string, []byte) error); ok {
		r1 = rf(ss, payloadRef, data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SharedStorageBlobDownloaded provides a mock function with given fields: ss, hash, size, payloadRef
func (_m *EventManager) SharedStorageBlobDownloaded(ss sharedstorage.Plugin, hash fftypes.Bytes32, size int64, payloadRef string) {
	_m.Called(ss, hash, size, payloadRef)
}

// Start provides a mock function with given fields:
func (_m *EventManager) Start() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SubscriptionUpdates provides a mock function with given fields:
func (_m *EventManager) SubscriptionUpdates() chan<- *fftypes.UUID {
	ret := _m.Called()

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

// TokenPoolCreated provides a mock function with given fields: ti, pool
func (_m *EventManager) TokenPoolCreated(ti tokens.Plugin, pool *tokens.TokenPool) error {
	ret := _m.Called(ti, pool)

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *tokens.TokenPool) error); ok {
		r0 = rf(ti, pool)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokensApproved provides a mock function with given fields: ti, approval
func (_m *EventManager) TokensApproved(ti tokens.Plugin, approval *tokens.TokenApproval) error {
	ret := _m.Called(ti, approval)

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

	var r0 error
	if rf, ok := ret.Get(0).(func(tokens.Plugin, *tokens.TokenTransfer) error); ok {
		r0 = rf(ti, transfer)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WaitStop provides a mock function with given fields:
func (_m *EventManager) WaitStop() {
	_m.Called()
}
