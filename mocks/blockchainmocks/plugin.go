// Code generated by mockery v2.33.2. DO NOT EDIT.

package blockchainmocks

import (
	cache "github.com/hyperledger/firefly/internal/cache"
	blockchain "github.com/hyperledger/firefly/pkg/blockchain"

	config "github.com/hyperledger/firefly-common/pkg/config"

	context "context"

	core "github.com/hyperledger/firefly/pkg/core"

	fftypes "github.com/hyperledger/firefly-common/pkg/fftypes"

	metrics "github.com/hyperledger/firefly/internal/metrics"

	mock "github.com/stretchr/testify/mock"
)

// Plugin is an autogenerated mock type for the Plugin type
type Plugin struct {
	mock.Mock
}

// AddContractListener provides a mock function with given fields: ctx, subscription
func (_m *Plugin) AddContractListener(ctx context.Context, subscription *core.ContractListener) error {
	ret := _m.Called(ctx, subscription)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.ContractListener) error); ok {
		r0 = rf(ctx, subscription)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddFireflySubscription provides a mock function with given fields: ctx, namespace, contract
func (_m *Plugin) AddFireflySubscription(ctx context.Context, namespace *core.Namespace, contract *blockchain.MultipartyContract) (string, error) {
	ret := _m.Called(ctx, namespace, contract)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Namespace, *blockchain.MultipartyContract) (string, error)); ok {
		return rf(ctx, namespace, contract)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.Namespace, *blockchain.MultipartyContract) string); ok {
		r0 = rf(ctx, namespace, contract)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.Namespace, *blockchain.MultipartyContract) error); ok {
		r1 = rf(ctx, namespace, contract)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Capabilities provides a mock function with given fields:
func (_m *Plugin) Capabilities() *blockchain.Capabilities {
	ret := _m.Called()

	var r0 *blockchain.Capabilities
	if rf, ok := ret.Get(0).(func() *blockchain.Capabilities); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*blockchain.Capabilities)
		}
	}

	return r0
}

// DeleteContractListener provides a mock function with given fields: ctx, subscription, okNotFound
func (_m *Plugin) DeleteContractListener(ctx context.Context, subscription *core.ContractListener, okNotFound bool) error {
	ret := _m.Called(ctx, subscription, okNotFound)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.ContractListener, bool) error); ok {
		r0 = rf(ctx, subscription, okNotFound)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeployContract provides a mock function with given fields: ctx, nsOpID, signingKey, definition, contract, input, options
func (_m *Plugin) DeployContract(ctx context.Context, nsOpID string, signingKey string, definition *fftypes.JSONAny, contract *fftypes.JSONAny, input []interface{}, options map[string]interface{}) error {
	ret := _m.Called(ctx, nsOpID, signingKey, definition, contract, input, options)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *fftypes.JSONAny, *fftypes.JSONAny, []interface{}, map[string]interface{}) error); ok {
		r0 = rf(ctx, nsOpID, signingKey, definition, contract, input, options)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GenerateErrorSignature provides a mock function with given fields: ctx, errorDef
func (_m *Plugin) GenerateErrorSignature(ctx context.Context, errorDef *fftypes.FFIErrorDefinition) string {
	ret := _m.Called(ctx, errorDef)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFIErrorDefinition) string); ok {
		r0 = rf(ctx, errorDef)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GenerateEventSignature provides a mock function with given fields: ctx, event
func (_m *Plugin) GenerateEventSignature(ctx context.Context, event *fftypes.FFIEventDefinition) string {
	ret := _m.Called(ctx, event)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFIEventDefinition) string); ok {
		r0 = rf(ctx, event)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GenerateFFI provides a mock function with given fields: ctx, generationRequest
func (_m *Plugin) GenerateFFI(ctx context.Context, generationRequest *fftypes.FFIGenerationRequest) (*fftypes.FFI, error) {
	ret := _m.Called(ctx, generationRequest)

	var r0 *fftypes.FFI
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFIGenerationRequest) (*fftypes.FFI, error)); ok {
		return rf(ctx, generationRequest)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFIGenerationRequest) *fftypes.FFI); ok {
		r0 = rf(ctx, generationRequest)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.FFI)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.FFIGenerationRequest) error); ok {
		r1 = rf(ctx, generationRequest)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAndConvertDeprecatedContractConfig provides a mock function with given fields: ctx
func (_m *Plugin) GetAndConvertDeprecatedContractConfig(ctx context.Context) (*fftypes.JSONAny, string, error) {
	ret := _m.Called(ctx)

	var r0 *fftypes.JSONAny
	var r1 string
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context) (*fftypes.JSONAny, string, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) *fftypes.JSONAny); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.JSONAny)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) string); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Get(1).(string)
	}

	if rf, ok := ret.Get(2).(func(context.Context) error); ok {
		r2 = rf(ctx)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetContractListenerStatus provides a mock function with given fields: ctx, namespace, subID, okNotFound
func (_m *Plugin) GetContractListenerStatus(ctx context.Context, namespace string, subID string, okNotFound bool) (bool, interface{}, error) {
	ret := _m.Called(ctx, namespace, subID, okNotFound)

	var r0 bool
	var r1 interface{}
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) (bool, interface{}, error)); ok {
		return rf(ctx, namespace, subID, okNotFound)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) bool); ok {
		r0 = rf(ctx, namespace, subID, okNotFound)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, bool) interface{}); ok {
		r1 = rf(ctx, namespace, subID, okNotFound)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(interface{})
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, bool) error); ok {
		r2 = rf(ctx, namespace, subID, okNotFound)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetFFIParamValidator provides a mock function with given fields: ctx
func (_m *Plugin) GetFFIParamValidator(ctx context.Context) (fftypes.FFIParamValidator, error) {
	ret := _m.Called(ctx)

	var r0 fftypes.FFIParamValidator
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (fftypes.FFIParamValidator, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) fftypes.FFIParamValidator); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.FFIParamValidator)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNetworkVersion provides a mock function with given fields: ctx, location
func (_m *Plugin) GetNetworkVersion(ctx context.Context, location *fftypes.JSONAny) (int, error) {
	ret := _m.Called(ctx, location)

	var r0 int
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.JSONAny) (int, error)); ok {
		return rf(ctx, location)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.JSONAny) int); ok {
		r0 = rf(ctx, location)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.JSONAny) error); ok {
		r1 = rf(ctx, location)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTransactionStatus provides a mock function with given fields: ctx, operation
func (_m *Plugin) GetTransactionStatus(ctx context.Context, operation *core.Operation) (interface{}, error) {
	ret := _m.Called(ctx, operation)

	var r0 interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.Operation) (interface{}, error)); ok {
		return rf(ctx, operation)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.Operation) interface{}); ok {
		r0 = rf(ctx, operation)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.Operation) error); ok {
		r1 = rf(ctx, operation)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Init provides a mock function with given fields: ctx, cancelCtx, _a2, _a3, cacheManager
func (_m *Plugin) Init(ctx context.Context, cancelCtx context.CancelFunc, _a2 config.Section, _a3 metrics.Manager, cacheManager cache.Manager) error {
	ret := _m.Called(ctx, cancelCtx, _a2, _a3, cacheManager)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, context.CancelFunc, config.Section, metrics.Manager, cache.Manager) error); ok {
		r0 = rf(ctx, cancelCtx, _a2, _a3, cacheManager)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InitConfig provides a mock function with given fields: _a0
func (_m *Plugin) InitConfig(_a0 config.Section) {
	_m.Called(_a0)
}

// InvokeContract provides a mock function with given fields: ctx, nsOpID, signingKey, location, parsedMethod, input, options, batch
func (_m *Plugin) InvokeContract(ctx context.Context, nsOpID string, signingKey string, location *fftypes.JSONAny, parsedMethod interface{}, input map[string]interface{}, options map[string]interface{}, batch *blockchain.BatchPin) error {
	ret := _m.Called(ctx, nsOpID, signingKey, location, parsedMethod, input, options, batch)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *fftypes.JSONAny, interface{}, map[string]interface{}, map[string]interface{}, *blockchain.BatchPin) error); ok {
		r0 = rf(ctx, nsOpID, signingKey, location, parsedMethod, input, options, batch)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Name provides a mock function with given fields:
func (_m *Plugin) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// NormalizeContractLocation provides a mock function with given fields: ctx, ntype, location
func (_m *Plugin) NormalizeContractLocation(ctx context.Context, ntype blockchain.NormalizeType, location *fftypes.JSONAny) (*fftypes.JSONAny, error) {
	ret := _m.Called(ctx, ntype, location)

	var r0 *fftypes.JSONAny
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, blockchain.NormalizeType, *fftypes.JSONAny) (*fftypes.JSONAny, error)); ok {
		return rf(ctx, ntype, location)
	}
	if rf, ok := ret.Get(0).(func(context.Context, blockchain.NormalizeType, *fftypes.JSONAny) *fftypes.JSONAny); ok {
		r0 = rf(ctx, ntype, location)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.JSONAny)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, blockchain.NormalizeType, *fftypes.JSONAny) error); ok {
		r1 = rf(ctx, ntype, location)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseInterface provides a mock function with given fields: ctx, method, errors
func (_m *Plugin) ParseInterface(ctx context.Context, method *fftypes.FFIMethod, errors []*fftypes.FFIError) (interface{}, error) {
	ret := _m.Called(ctx, method, errors)

	var r0 interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFIMethod, []*fftypes.FFIError) (interface{}, error)); ok {
		return rf(ctx, method, errors)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFIMethod, []*fftypes.FFIError) interface{}); ok {
		r0 = rf(ctx, method, errors)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.FFIMethod, []*fftypes.FFIError) error); ok {
		r1 = rf(ctx, method, errors)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// QueryContract provides a mock function with given fields: ctx, signingKey, location, parsedMethod, input, options
func (_m *Plugin) QueryContract(ctx context.Context, signingKey string, location *fftypes.JSONAny, parsedMethod interface{}, input map[string]interface{}, options map[string]interface{}) (interface{}, error) {
	ret := _m.Called(ctx, signingKey, location, parsedMethod, input, options)

	var r0 interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.JSONAny, interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error)); ok {
		return rf(ctx, signingKey, location, parsedMethod, input, options)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, *fftypes.JSONAny, interface{}, map[string]interface{}, map[string]interface{}) interface{}); ok {
		r0 = rf(ctx, signingKey, location, parsedMethod, input, options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, *fftypes.JSONAny, interface{}, map[string]interface{}, map[string]interface{}) error); ok {
		r1 = rf(ctx, signingKey, location, parsedMethod, input, options)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveFireflySubscription provides a mock function with given fields: ctx, subID
func (_m *Plugin) RemoveFireflySubscription(ctx context.Context, subID string) {
	_m.Called(ctx, subID)
}

// ResolveSigningKey provides a mock function with given fields: ctx, keyRef, intent
func (_m *Plugin) ResolveSigningKey(ctx context.Context, keyRef string, intent blockchain.ResolveKeyIntent) (string, error) {
	ret := _m.Called(ctx, keyRef, intent)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, blockchain.ResolveKeyIntent) (string, error)); ok {
		return rf(ctx, keyRef, intent)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, blockchain.ResolveKeyIntent) string); ok {
		r0 = rf(ctx, keyRef, intent)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, blockchain.ResolveKeyIntent) error); ok {
		r1 = rf(ctx, keyRef, intent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetHandler provides a mock function with given fields: namespace, handler
func (_m *Plugin) SetHandler(namespace string, handler blockchain.Callbacks) {
	_m.Called(namespace, handler)
}

// SetOperationHandler provides a mock function with given fields: namespace, handler
func (_m *Plugin) SetOperationHandler(namespace string, handler core.OperationCallbacks) {
	_m.Called(namespace, handler)
}

// StartNamespace provides a mock function with given fields: ctx, namespace
func (_m *Plugin) StartNamespace(ctx context.Context, namespace string) error {
	ret := _m.Called(ctx, namespace)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, namespace)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StopNamespace provides a mock function with given fields: ctx, namespace
func (_m *Plugin) StopNamespace(ctx context.Context, namespace string) error {
	ret := _m.Called(ctx, namespace)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, namespace)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SubmitBatchPin provides a mock function with given fields: ctx, nsOpID, networkNamespace, signingKey, batch, location
func (_m *Plugin) SubmitBatchPin(ctx context.Context, nsOpID string, networkNamespace string, signingKey string, batch *blockchain.BatchPin, location *fftypes.JSONAny) error {
	ret := _m.Called(ctx, nsOpID, networkNamespace, signingKey, batch, location)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *blockchain.BatchPin, *fftypes.JSONAny) error); ok {
		r0 = rf(ctx, nsOpID, networkNamespace, signingKey, batch, location)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SubmitNetworkAction provides a mock function with given fields: ctx, nsOpID, signingKey, action, location
func (_m *Plugin) SubmitNetworkAction(ctx context.Context, nsOpID string, signingKey string, action fftypes.FFEnum, location *fftypes.JSONAny) error {
	ret := _m.Called(ctx, nsOpID, signingKey, action, location)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, fftypes.FFEnum, *fftypes.JSONAny) error); ok {
		r0 = rf(ctx, nsOpID, signingKey, action, location)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateInvokeRequest provides a mock function with given fields: ctx, parsedMethod, input, hasMessage
func (_m *Plugin) ValidateInvokeRequest(ctx context.Context, parsedMethod interface{}, input map[string]interface{}, hasMessage bool) error {
	ret := _m.Called(ctx, parsedMethod, input, hasMessage)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, interface{}, map[string]interface{}, bool) error); ok {
		r0 = rf(ctx, parsedMethod, input, hasMessage)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VerifierType provides a mock function with given fields:
func (_m *Plugin) VerifierType() fftypes.FFEnum {
	ret := _m.Called()

	var r0 fftypes.FFEnum
	if rf, ok := ret.Get(0).(func() fftypes.FFEnum); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(fftypes.FFEnum)
	}

	return r0
}

// NewPlugin creates a new instance of Plugin. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPlugin(t interface {
	mock.TestingT
	Cleanup(func())
}) *Plugin {
	mock := &Plugin{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
