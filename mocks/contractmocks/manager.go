// Code generated by mockery v1.0.0. DO NOT EDIT.

package contractmocks

import (
	context "context"

	database "github.com/hyperledger/firefly/pkg/database"

	fftypes "github.com/hyperledger/firefly/pkg/fftypes"

	mock "github.com/stretchr/testify/mock"

	openapi3 "github.com/getkin/kin-openapi/openapi3"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// AddContractSubscription provides a mock function with given fields: ctx, ns, sub
func (_m *Manager) AddContractSubscription(ctx context.Context, ns string, sub *fftypes.ContractSubscriptionInput) (*fftypes.ContractSubscription, error) {
	ret := _m.Called(ctx, ns, sub)

	var r0 *fftypes.ContractSubscription
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.ContractSubscriptionInput) *fftypes.ContractSubscription); ok {
		r0 = rf(ctx, ns, sub)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.ContractSubscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.ContractSubscriptionInput) error); ok {
		r1 = rf(ctx, ns, sub)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BroadcastContractAPI provides a mock function with given fields: ctx, ns, api, waitConfirm
func (_m *Manager) BroadcastContractAPI(ctx context.Context, ns string, api *fftypes.ContractAPI, waitConfirm bool) (*fftypes.ContractAPI, error) {
	ret := _m.Called(ctx, ns, api, waitConfirm)

	var r0 *fftypes.ContractAPI
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.ContractAPI, bool) *fftypes.ContractAPI); ok {
		r0 = rf(ctx, ns, api, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.ContractAPI)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.ContractAPI, bool) error); ok {
		r1 = rf(ctx, ns, api, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BroadcastFFI provides a mock function with given fields: ctx, ns, ffi, waitConfirm
func (_m *Manager) BroadcastFFI(ctx context.Context, ns string, ffi *fftypes.FFI, waitConfirm bool) (*fftypes.FFI, error) {
	ret := _m.Called(ctx, ns, ffi, waitConfirm)

	var r0 *fftypes.FFI
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.FFI, bool) *fftypes.FFI); ok {
		r0 = rf(ctx, ns, ffi, waitConfirm)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.FFI)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.FFI, bool) error); ok {
		r1 = rf(ctx, ns, ffi, waitConfirm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteContractSubscriptionByNameOrID provides a mock function with given fields: ctx, ns, nameOrID
func (_m *Manager) DeleteContractSubscriptionByNameOrID(ctx context.Context, ns string, nameOrID string) error {
	ret := _m.Called(ctx, ns, nameOrID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, ns, nameOrID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetContractAPI provides a mock function with given fields: ctx, httpServerURL, ns, apiName
func (_m *Manager) GetContractAPI(ctx context.Context, httpServerURL string, ns string, apiName string) (*fftypes.ContractAPI, error) {
	ret := _m.Called(ctx, httpServerURL, ns, apiName)

	var r0 *fftypes.ContractAPI
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) *fftypes.ContractAPI); ok {
		r0 = rf(ctx, httpServerURL, ns, apiName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.ContractAPI)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, httpServerURL, ns, apiName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetContractAPISwagger provides a mock function with given fields: ctx, httpServerURL, ns, apiName
func (_m *Manager) GetContractAPISwagger(ctx context.Context, httpServerURL string, ns string, apiName string) (*openapi3.T, error) {
	ret := _m.Called(ctx, httpServerURL, ns, apiName)

	var r0 *openapi3.T
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) *openapi3.T); ok {
		r0 = rf(ctx, httpServerURL, ns, apiName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*openapi3.T)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, httpServerURL, ns, apiName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetContractAPIs provides a mock function with given fields: ctx, httpServerURL, ns, filter
func (_m *Manager) GetContractAPIs(ctx context.Context, httpServerURL string, ns string, filter database.AndFilter) ([]*fftypes.ContractAPI, *database.FilterResult, error) {
	ret := _m.Called(ctx, httpServerURL, ns, filter)

	var r0 []*fftypes.ContractAPI
	if rf, ok := ret.Get(0).(func(context.Context, string, string, database.AndFilter) []*fftypes.ContractAPI); ok {
		r0 = rf(ctx, httpServerURL, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.ContractAPI)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, httpServerURL, ns, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, string, database.AndFilter) error); ok {
		r2 = rf(ctx, httpServerURL, ns, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetContractEventByID provides a mock function with given fields: ctx, id
func (_m *Manager) GetContractEventByID(ctx context.Context, id *fftypes.UUID) (*fftypes.ContractEvent, error) {
	ret := _m.Called(ctx, id)

	var r0 *fftypes.ContractEvent
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID) *fftypes.ContractEvent); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.ContractEvent)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetContractEvents provides a mock function with given fields: ctx, ns, filter
func (_m *Manager) GetContractEvents(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.ContractEvent, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.ContractEvent
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.ContractEvent); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.ContractEvent)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetContractSubscriptionByNameOrID provides a mock function with given fields: ctx, ns, nameOrID
func (_m *Manager) GetContractSubscriptionByNameOrID(ctx context.Context, ns string, nameOrID string) (*fftypes.ContractSubscription, error) {
	ret := _m.Called(ctx, ns, nameOrID)

	var r0 *fftypes.ContractSubscription
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *fftypes.ContractSubscription); ok {
		r0 = rf(ctx, ns, nameOrID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.ContractSubscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, ns, nameOrID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetContractSubscriptions provides a mock function with given fields: ctx, ns, filter
func (_m *Manager) GetContractSubscriptions(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.ContractSubscription, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.ContractSubscription
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.ContractSubscription); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.ContractSubscription)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetFFI provides a mock function with given fields: ctx, ns, name, version
func (_m *Manager) GetFFI(ctx context.Context, ns string, name string, version string) (*fftypes.FFI, error) {
	ret := _m.Called(ctx, ns, name, version)

	var r0 *fftypes.FFI
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) *fftypes.FFI); ok {
		r0 = rf(ctx, ns, name, version)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.FFI)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, ns, name, version)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetFFIByID provides a mock function with given fields: ctx, id
func (_m *Manager) GetFFIByID(ctx context.Context, id *fftypes.UUID) (*fftypes.FFI, error) {
	ret := _m.Called(ctx, id)

	var r0 *fftypes.FFI
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID) *fftypes.FFI); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.FFI)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetFFIByIDWithChildren provides a mock function with given fields: ctx, id
func (_m *Manager) GetFFIByIDWithChildren(ctx context.Context, id *fftypes.UUID) (*fftypes.FFI, error) {
	ret := _m.Called(ctx, id)

	var r0 *fftypes.FFI
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.UUID) *fftypes.FFI); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.FFI)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.UUID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetFFIs provides a mock function with given fields: ctx, ns, filter
func (_m *Manager) GetFFIs(ctx context.Context, ns string, filter database.AndFilter) ([]*fftypes.FFI, *database.FilterResult, error) {
	ret := _m.Called(ctx, ns, filter)

	var r0 []*fftypes.FFI
	if rf, ok := ret.Get(0).(func(context.Context, string, database.AndFilter) []*fftypes.FFI); ok {
		r0 = rf(ctx, ns, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*fftypes.FFI)
		}
	}

	var r1 *database.FilterResult
	if rf, ok := ret.Get(1).(func(context.Context, string, database.AndFilter) *database.FilterResult); ok {
		r1 = rf(ctx, ns, filter)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*database.FilterResult)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string, database.AndFilter) error); ok {
		r2 = rf(ctx, ns, filter)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// InvokeContract provides a mock function with given fields: ctx, ns, req
func (_m *Manager) InvokeContract(ctx context.Context, ns string, req *fftypes.InvokeContractRequest) (interface{}, error) {
	ret := _m.Called(ctx, ns, req)

	var r0 interface{}
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.InvokeContractRequest) interface{}); ok {
		r0 = rf(ctx, ns, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.InvokeContractRequest) error); ok {
		r1 = rf(ctx, ns, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InvokeContractAPI provides a mock function with given fields: ctx, ns, apiName, methodPath, req
func (_m *Manager) InvokeContractAPI(ctx context.Context, ns string, apiName string, methodPath string, req *fftypes.InvokeContractRequest) (interface{}, error) {
	ret := _m.Called(ctx, ns, apiName, methodPath, req)

	var r0 interface{}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *fftypes.InvokeContractRequest) interface{}); ok {
		r0 = rf(ctx, ns, apiName, methodPath, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, *fftypes.InvokeContractRequest) error); ok {
		r1 = rf(ctx, ns, apiName, methodPath, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SubscribeContract provides a mock function with given fields: ctx, ns, eventPath, req
func (_m *Manager) SubscribeContract(ctx context.Context, ns string, eventPath string, req *fftypes.ContractSubscribeRequest) (*fftypes.ContractSubscription, error) {
	ret := _m.Called(ctx, ns, eventPath, req)

	var r0 *fftypes.ContractSubscription
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *fftypes.ContractSubscribeRequest) *fftypes.ContractSubscription); ok {
		r0 = rf(ctx, ns, eventPath, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.ContractSubscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, *fftypes.ContractSubscribeRequest) error); ok {
		r1 = rf(ctx, ns, eventPath, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SubscribeContractAPI provides a mock function with given fields: ctx, ns, apiName, eventPath, req
func (_m *Manager) SubscribeContractAPI(ctx context.Context, ns string, apiName string, eventPath string, req *fftypes.ContractSubscribeRequest) (*fftypes.ContractSubscription, error) {
	ret := _m.Called(ctx, ns, apiName, eventPath, req)

	var r0 *fftypes.ContractSubscription
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *fftypes.ContractSubscribeRequest) *fftypes.ContractSubscription); ok {
		r0 = rf(ctx, ns, apiName, eventPath, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.ContractSubscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, *fftypes.ContractSubscribeRequest) error); ok {
		r1 = rf(ctx, ns, apiName, eventPath, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateFFIAndSetPathnames provides a mock function with given fields: ctx, ffi
func (_m *Manager) ValidateFFIAndSetPathnames(ctx context.Context, ffi *fftypes.FFI) error {
	ret := _m.Called(ctx, ffi)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFI) error); ok {
		r0 = rf(ctx, ffi)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
