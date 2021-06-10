// Code generated by mockery v1.0.0. DO NOT EDIT.

package orchestratormocks

import (
	context "context"

	broadcast "github.com/hyperledger-labs/firefly/internal/broadcast"

	data "github.com/hyperledger-labs/firefly/internal/data"

	database "github.com/hyperledger-labs/firefly/pkg/database"

	events "github.com/hyperledger-labs/firefly/internal/events"

	fftypes "github.com/hyperledger-labs/firefly/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	networkmap "github.com/hyperledger-labs/firefly/internal/networkmap"

	privatemessaging "github.com/hyperledger-labs/firefly/internal/privatemessaging"
)

// Orchestrator is an autogenerated mock type for the Orchestrator type
type Orchestrator struct {
	mock.Mock
}

// Broadcast provides a mock function with given fields:
func (_m *Orchestrator) Broadcast() broadcast.Manager {
	ret := _m.Called()

	var r0 broadcast.Manager
	if rf, ok := ret.Get(0).(func() broadcast.Manager); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(broadcast.Manager)
		}
	}

	return r0
}

// CreateSubscription provides a mock function with given fields: ctx, ns, subDef
func (_m *Orchestrator) CreateSubscription(ctx context.Context, ns string, subDef *fftypes.Subscription) (*fftypes.Subscription, error) {
	ret := _m.Called(ctx, ns, subDef)

	var r0 *fftypes.Subscription
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.Subscription) *fftypes.Subscription); ok {
		r0 = rf(ctx, ns, subDef)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.Subscription) error); ok {
		r1 = rf(ctx, ns, subDef)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Data provides a mock function with given fields:
func (_m *Orchestrator) Data() data.Manager {
	ret := _m.Called()

	var r0 data.Manager
	if rf, ok := ret.Get(0).(func() data.Manager); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(data.Manager)
		}
	}

	return r0
}

// DeleteSubscription provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) DeleteSubscription(ctx context.Context, ns string, id string) error {
	ret := _m.Called(ctx, ns, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, ns, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Events provides a mock function with given fields:
func (_m *Orchestrator) Events() events.EventManager {
	ret := _m.Called()

	var r0 events.EventManager
	if rf, ok := ret.Get(0).(func() events.EventManager); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(events.EventManager)
		}
	}

	return r0
}

// GetBatchByID provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetBatchByID(ctx context.Context, ns string, id string) (*fftypes.Batch, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Batch
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Batch); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Batch)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetBatches provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetBatches(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Batch, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Batch
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Batch); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Batch)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetData provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetData(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Data, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Data
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Data); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Data)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDataByID provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetDataByID(ctx context.Context, ns string, id string) (*fftypes.Data, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Data
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Data); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Data)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDatatypeByID provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetDatatypeByID(ctx context.Context, ns string, id string) (*fftypes.Datatype, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Datatype
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Datatype); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Datatype)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDatatypes provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetDatatypes(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Datatype, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Datatype
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Datatype); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Datatype)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetEventByID provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetEventByID(ctx context.Context, ns string, id string) (*fftypes.Event, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Event
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Event); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Event)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetEvents provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetEvents(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Event, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Event
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Event); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Event)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessageByID provides a mock function with given fields: ctx, ns, id, withValues
func (_m *Orchestrator) GetMessageByID(ctx context.Context, ns string, id string, withValues bool) (*fftypes.MessageInput, error) {
	ret := _m.Called(ctx, ns, id, withValues)

	var r0 *fftypes.MessageInput
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) *fftypes.MessageInput); ok {
		r0 = rf(ctx, ns, id, withValues)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.MessageInput)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, bool) error); ok {
		r1 = rf(ctx, ns, id, withValues)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessageData provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetMessageData(ctx context.Context, ns string, id string) ([]*fftypes.Data, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 []*fftypes.Data
	if rf, ok := ret.Get(0).(func(context.Context, string, string) []*fftypes.Data); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Data)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessageEvents provides a mock function with given fields: ctx, ns, id, filter
func (_m *Orchestrator) GetMessageEvents(ctx context.Context, ns string, id string, filter database.AndFilter) ([]*fftypes.Event, error) {
	ret := _m.Called(ctx, ns, id, filter)

	var r0 []*fftypes.Event
	if rf, ok := ret.Get(0).(func(context.Context, string, string, database.AndFilter) []*fftypes.Event); ok {
		r0 = rf(ctx, ns, id, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Event)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, id, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessageOperations provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetMessageOperations(ctx context.Context, ns string, id string) ([]*fftypes.Operation, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 []*fftypes.Operation
	if rf, ok := ret.Get(0).(func(context.Context, string, string) []*fftypes.Operation); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Operation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessageTransaction provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetMessageTransaction(ctx context.Context, ns string, id string) (*fftypes.Transaction, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Transaction
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Transaction); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessages provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetMessages(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Message, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Message); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessagesForData provides a mock function with given fields: ctx, ns, dataID, filter
func (_m *Orchestrator) GetMessagesForData(ctx context.Context, ns string, dataID string, filter database.AndFilter) ([]*fftypes.Message, error) {
	ret := _m.Called(ctx, ns, dataID, filter)

	var r0 []*fftypes.Message
	if rf, ok := ret.Get(0).(func(context.Context, string, string, database.AndFilter) []*fftypes.Message); ok {
		r0 = rf(ctx, ns, dataID, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Message)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, dataID, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNamespace provides a mock function with given fields: ctx, ns
func (_m *Orchestrator) GetNamespace(ctx context.Context, ns string) (*fftypes.Namespace, error) {
	ret := _m.Called(ctx, ns)

	var r0 *fftypes.Namespace
	if rf, ok := ret.Get(0).(func(context.Context, string) *fftypes.Namespace); ok {
		r0 = rf(ctx, ns)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Namespace)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, ns)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNamespaces provides a mock function with given fields: ctx, filter
func (_m *Orchestrator) GetNamespaces(ctx context.Context, filter database.AndFilter) ([]*fftypes.Namespace, error) {
	ret := _m.Called(ctx, filter)

	var r0 []*fftypes.Namespace
	if rf, ok := ret.Get(0).(func(context.Context, database.AndFilter) []*fftypes.Namespace); ok {
		r0 = rf(ctx, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Namespace)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, database.AndFilter) error); ok {
		r1 = rf(ctx, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetOperationByID provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetOperationByID(ctx context.Context, ns string, id string) (*fftypes.Operation, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Operation
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Operation); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Operation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetOperations provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetOperations(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Operation, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Operation
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Operation); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Operation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetStatus provides a mock function with given fields: ctx
func (_m *Orchestrator) GetStatus(ctx context.Context) (*fftypes.NodeStatus, error) {
	ret := _m.Called(ctx)

	var r0 *fftypes.NodeStatus
	if rf, ok := ret.Get(0).(func(context.Context) *fftypes.NodeStatus); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.NodeStatus)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetSubscriptionByID provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetSubscriptionByID(ctx context.Context, ns string, id string) (*fftypes.Subscription, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Subscription
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Subscription); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetSubscriptions provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetSubscriptions(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Subscription, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Subscription
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Subscription); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTransactionByID provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetTransactionByID(ctx context.Context, ns string, id string) (*fftypes.Transaction, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 *fftypes.Transaction
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.Transaction); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTransactionOperations provides a mock function with given fields: ctx, ns, id
func (_m *Orchestrator) GetTransactionOperations(ctx context.Context, ns string, id string) ([]*fftypes.Operation, error) {
	ret := _m.Called(ctx, ns, id)

	var r0 []*fftypes.Operation
	if rf, ok := ret.Get(0).(func(context.Context, string, string) []*fftypes.Operation); ok {
		r0 = rf(ctx, ns, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Operation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTransactions provides a mock function with given fields: ctx, ns, filter
func (_m *Orchestrator) GetTransactions(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.Transaction, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.Transaction
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.Transaction); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) error); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Init provides a mock function with given fields: ctx
func (_m *Orchestrator) Init(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NetworkMap provides a mock function with given fields:
func (_m *Orchestrator) NetworkMap() networkmap.Manager {
	ret := _m.Called()

	var r0 networkmap.Manager
	if rf, ok := ret.Get(0).(func() networkmap.Manager); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(networkmap.Manager)
		}
	}

	return r0
}

// PrivateMessaging provides a mock function with given fields:
func (_m *Orchestrator) PrivateMessaging() privatemessaging.Manager {
	ret := _m.Called()

	var r0 privatemessaging.Manager
	if rf, ok := ret.Get(0).(func() privatemessaging.Manager); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(privatemessaging.Manager)
		}
	}

	return r0
}

// Start provides a mock function with given fields:
func (_m *Orchestrator) Start() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WaitStop provides a mock function with given fields:
func (_m *Orchestrator) WaitStop() {
	_m.Called()
}
