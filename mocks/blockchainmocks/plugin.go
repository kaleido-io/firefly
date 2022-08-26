// Code generated by mockery v1.0.0. DO NOT EDIT.

package blockchainmocks

import (
	config "github.com/hyperledger/firefly-common/pkg/config"
	blockchain "github.com/hyperledger/firefly/pkg/blockchain"

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
func (_m *Plugin) AddContractListener(ctx context.Context, subscription *core.ContractListenerInput) error {
	ret := _m.Called(ctx, subscription)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.ContractListenerInput) error); ok {
		r0 = rf(ctx, subscription)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddFireflySubscription provides a mock function with given fields: ctx, namespace, location, firstEvent
func (_m *Plugin) AddFireflySubscription(ctx context.Context, namespace *core.Namespace, location *fftypes.JSONAny, firstEvent string) (string, error) {
	ret := _m.Called(ctx, namespace, location, firstEvent)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, *core.Namespace, *fftypes.JSONAny, string) string); ok {
		r0 = rf(ctx, namespace, location, firstEvent)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *core.Namespace, *fftypes.JSONAny, string) error); ok {
		r1 = rf(ctx, namespace, location, firstEvent)
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

// DeleteContractListener provides a mock function with given fields: ctx, subscription
func (_m *Plugin) DeleteContractListener(ctx context.Context, subscription *core.ContractListener) error {
	ret := _m.Called(ctx, subscription)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.ContractListener) error); ok {
		r0 = rf(ctx, subscription)
	} else {
		r0 = ret.Error(0)
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
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.FFIGenerationRequest) *fftypes.FFI); ok {
		r0 = rf(ctx, generationRequest)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.FFI)
		}
	}

	var r1 error
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
	if rf, ok := ret.Get(0).(func(context.Context) *fftypes.JSONAny); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.JSONAny)
		}
	}

	var r1 string
	if rf, ok := ret.Get(1).(func(context.Context) string); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Get(1).(string)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context) error); ok {
		r2 = rf(ctx)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetFFIParamValidator provides a mock function with given fields: ctx
func (_m *Plugin) GetFFIParamValidator(ctx context.Context) (fftypes.FFIParamValidator, error) {
	ret := _m.Called(ctx)

	var r0 fftypes.FFIParamValidator
	if rf, ok := ret.Get(0).(func(context.Context) fftypes.FFIParamValidator); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fftypes.FFIParamValidator)
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

// GetNetworkVersion provides a mock function with given fields: ctx, location
func (_m *Plugin) GetNetworkVersion(ctx context.Context, location *fftypes.JSONAny) (int, error) {
	ret := _m.Called(ctx, location)

	var r0 int
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.JSONAny) int); ok {
		r0 = rf(ctx, location)
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.JSONAny) error); ok {
		r1 = rf(ctx, location)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Init provides a mock function with given fields: ctx, _a1, _a2
func (_m *Plugin) Init(ctx context.Context, _a1 config.Section, _a2 metrics.Manager) error {
	ret := _m.Called(ctx, _a1, _a2)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, config.Section, metrics.Manager) error); ok {
		r0 = rf(ctx, _a1, _a2)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InitConfig provides a mock function with given fields: _a0
func (_m *Plugin) InitConfig(_a0 config.Section) {
	_m.Called(_a0)
}

// InvokeContract provides a mock function with given fields: ctx, nsOpID, signingKey, location, method, input, options
func (_m *Plugin) InvokeContract(ctx context.Context, nsOpID string, signingKey string, location *fftypes.JSONAny, method *fftypes.FFIMethod, input map[string]interface{}, options map[string]interface{}) error {
	ret := _m.Called(ctx, nsOpID, signingKey, location, method, input, options)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *fftypes.JSONAny, *fftypes.FFIMethod, map[string]interface{}, map[string]interface{}) error); ok {
		r0 = rf(ctx, nsOpID, signingKey, location, method, input, options)
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

// NormalizeContractLocation provides a mock function with given fields: ctx, location
func (_m *Plugin) NormalizeContractLocation(ctx context.Context, location *fftypes.JSONAny) (*fftypes.JSONAny, error) {
	ret := _m.Called(ctx, location)

	var r0 *fftypes.JSONAny
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.JSONAny) *fftypes.JSONAny); ok {
		r0 = rf(ctx, location)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*fftypes.JSONAny)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.JSONAny) error); ok {
		r1 = rf(ctx, location)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NormalizeSigningKey provides a mock function with given fields: ctx, keyRef
func (_m *Plugin) NormalizeSigningKey(ctx context.Context, keyRef string) (string, error) {
	ret := _m.Called(ctx, keyRef)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, keyRef)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, keyRef)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// QueryContract provides a mock function with given fields: ctx, location, method, input, options
func (_m *Plugin) QueryContract(ctx context.Context, location *fftypes.JSONAny, method *fftypes.FFIMethod, input map[string]interface{}, options map[string]interface{}) (interface{}, error) {
	ret := _m.Called(ctx, location, method, input, options)

	var r0 interface{}
	if rf, ok := ret.Get(0).(func(context.Context, *fftypes.JSONAny, *fftypes.FFIMethod, map[string]interface{}, map[string]interface{}) interface{}); ok {
		r0 = rf(ctx, location, method, input, options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *fftypes.JSONAny, *fftypes.FFIMethod, map[string]interface{}, map[string]interface{}) error); ok {
		r1 = rf(ctx, location, method, input, options)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveFireflySubscription provides a mock function with given fields: ctx, subID
func (_m *Plugin) RemoveFireflySubscription(ctx context.Context, subID string) {
	_m.Called(ctx, subID)
}

// SetHandler provides a mock function with given fields: namespace, handler
func (_m *Plugin) SetHandler(namespace string, handler blockchain.Callbacks) {
	_m.Called(namespace, handler)
}

// SetOperationHandler provides a mock function with given fields: namespace, handler
func (_m *Plugin) SetOperationHandler(namespace string, handler core.OperationCallbacks) {
	_m.Called(namespace, handler)
}

// Start provides a mock function with given fields:
func (_m *Plugin) Start() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
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
