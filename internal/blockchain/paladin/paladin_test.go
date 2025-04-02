// Copyright © 2025 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package paladin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/fftls"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly/internal/blockchain/common"
	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/mocks/blockchainmocks"
	"github.com/hyperledger/firefly/mocks/coremocks"
	"github.com/hyperledger/firefly/mocks/metricsmocks"
	"github.com/hyperledger/firefly/mocks/paladinclientmocks"
	"github.com/hyperledger/firefly/mocks/paladinrpcclientmocks"
	"github.com/hyperledger/firefly/pkg/blockchain"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var utConfig = config.RootSection("paladin_unit_tests")
var utRPCConfig = utConfig.SubSection(PaladinRPCClientConfigKey)

var get = &abi.Entry{
	Name: "get",
	Outputs: abi.ParameterArray{{
		Name:         "retVal",
		Type:         "uint256",
		InternalType: "uint256",
	}},
	StateMutability: "view",
	Type:            "function",
}

var set = &abi.Entry{
	Name: "set",
	Inputs: abi.ParameterArray{{
		Name:         "x",
		Type:         "uint256",
		InternalType: "uint256",
	}},
	Outputs: abi.ParameterArray{{
		Name:         "value",
		Type:         "uint256",
		InternalType: "uint256",
	}},
	StateMutability: "nonpayable",
	Type:            "function",
}

var contractABI = abi.ABI{get, set}

func resetConf(p *Paladin) {
	coreconfig.Reset()
	p.InitConfig(utConfig)
}

func NewTestPaladin(t *testing.T) (*Paladin, *paladinclientmocks.PaladinClient, *paladinclientmocks.PTX, context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	mm := &metricsmocks.Manager{}
	mm.On("IsMetricsEnabled").Return(true)
	mm.On("BlockchainTransaction", mock.Anything, mock.Anything).Return(nil)
	mm.On("BlockchainContractDeployment", mock.Anything, mock.Anything).Return(nil)
	mm.On("BlockchainQuery", mock.Anything, mock.Anything).Return(nil)
	p := &Paladin{
		ctx:       ctx,
		cancelCtx: cancel,
		metrics:   mm,
		callbacks: common.NewBlockchainCallbacks(),
		wsconn:    make(map[string]pldclient.PaladinWSClient),
	}

	mockPaladinClient := paladinclientmocks.NewPaladinClient(t)
	mockPTX := paladinclientmocks.NewPTX(t)

	mockPaladinClient.On("PTX").Return(mockPTX).Maybe()

	p.httpClient = mockPaladinClient
	p.pldClient = mockPaladinClient

	return p, mockPaladinClient, mockPTX, ctx, cancel
}

func TestInitBadHTTPConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Paladin{}
	resetConf(p)
	tlsConf := utRPCConfig.SubSection("tls")
	tlsConf.Set(fftls.HTTPConfTLSEnabled, true)
	tlsConf.Set(fftls.HTTPConfTLSCAFile, "!!!!!badness")
	err := p.Init(ctx, cancel, utConfig, nil, nil)
	assert.Regexp(t, "FF00153", err)
}

func TestInitHTTPClientFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Paladin{}
	resetConf(p)
	utRPCConfig.Set("url", "bad")
	err := p.Init(ctx, cancel, utConfig, nil, nil)
	assert.Regexp(t, "PD020501", err)
}

func TestInitSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mm := &metricsmocks.Manager{}
	p := &Paladin{}
	resetConf(p)
	utRPCConfig.Set("url", "https://localhost:1234")
	utRPCConfig.Set("ws.url", "ws://localhost:1234")
	err := p.Init(ctx, cancel, utConfig, mm, nil)
	require.NoError(t, err)
	assert.Equal(t, mm, p.metrics)
	assert.NotNil(t, p.Capabilities())

}

func TestName(t *testing.T) {
	p, _, _, _, _ := NewTestPaladin(t)
	assert.Equal(t, "paladin", p.Name())
}

func TestVerifierType(t *testing.T) {
	p, _, _, _, _ := NewTestPaladin(t)
	assert.Equal(t, core.VerifierTypeEthAddress, p.VerifierType())
}

func TestStartNamespace(t *testing.T) {
	p, mockClient, mockPTX, ctx, cancel := NewTestPaladin(t)
	defer cancel()

	mockWSPTX := paladinclientmocks.NewPTX(t)
	mockWS := paladinclientmocks.NewPaladinWSClient(t)
	mockWS.On("PTX").Return(mockWSPTX).Maybe()
	mockWS.On("Close").Return().Maybe()

	// error starting receipt listener
	mockPTX.On("StartReceiptListener", mock.Anything, "ns1").Return(false, errors.New("start rl err")).Once()
	err := p.StartNamespace(ctx, "ns1")
	assert.ErrorContains(t, err, "start rl err")

	// error creating receipt listener
	mockPTX.On("StartReceiptListener", mock.Anything, "ns1").Return(false, errors.New("PD012238")).Once()
	mockPTX.On("CreateReceiptListener", mock.Anything, &pldapi.TransactionReceiptListener{
		Name: "ns1",
	}).Return(false, errors.New("create rl err")).Once()
	err = p.StartNamespace(ctx, "ns1")
	assert.ErrorContains(t, err, "create rl err")

	// error starting websocket
	mockPTX.On("StartReceiptListener", mock.Anything, "ns1").Return(true, nil)
	mockClient.On("WebSocket", mock.Anything, mock.Anything).Return(nil, errors.New("start ws err")).Once()
	err = p.StartNamespace(ctx, "ns1")
	assert.ErrorContains(t, err, "start ws err")

	// error subscribing to receipts
	mockClient.On("WebSocket", mock.Anything, mock.Anything).Return(mockWS, nil)
	mockWSPTX.On("SubscribeReceipts", mock.Anything, "ns1").Return(nil, errors.New("subscribe err")).Once()
	err = p.StartNamespace(ctx, "ns1")
	assert.ErrorContains(t, err, "subscribe err")

	// success
	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(make(chan rpcclient.RPCSubscriptionNotification)).Maybe()
	mockWSPTX.On("SubscribeReceipts", mock.Anything, "ns1").Return(sub, nil)
	err = p.StartNamespace(ctx, "ns1")
	assert.NoError(t, err)
}

func TestBatchEventLoopErrorUnmarshallingReceipts(t *testing.T) {
	p, _, _, _, cancel := NewTestPaladin(t)
	defer cancel()

	mockWSClient := paladinclientmocks.NewPaladinWSClient(t)
	mockWSClient.On("Close").Return()
	p.wsconn["ns1"] = mockWSClient

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(tktypes.RawJSON(`{"receipts": 4}`))
	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)
	// if we don't exit with an error this test will fail by timing out
	p.batchEventLoop("ns1", sub)
}

func TestBatchEventLoopErrorFetchingTransaction(t *testing.T) {
	p, _, mockPTX, _, cancel := NewTestPaladin(t)
	defer cancel()

	mockWSClient := paladinclientmocks.NewPaladinWSClient(t)
	mockWSClient.On("Close").Return()
	p.wsconn["ns1"] = mockWSClient

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(tktypes.RawJSON(`{"receipts": [{"id": "c920c994-8beb-49a8-9141-48f0fa61b050"}]}`))
	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	mockPTX.On("GetTransactionFull", mock.Anything, uuid.MustParse("c920c994-8beb-49a8-9141-48f0fa61b050")).
		Return(nil, errors.New("get tx err"))
	// if we don't exit with an error this test will fail by timing out
	p.batchEventLoop("ns1", sub)
}

func TestBatchEventLoopSuccess(t *testing.T) {
	p, _, mockPTX, _, cancel := NewTestPaladin(t)
	defer cancel()

	mockWSClient := paladinclientmocks.NewPaladinWSClient(t)
	mockWSClient.On("Close").Return().Maybe()
	p.wsconn["ns1"] = mockWSClient

	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()
	txHash1 := tktypes.MustParseBytes32(tktypes.RandHex(32))
	txHash2 := tktypes.MustParseBytes32(tktypes.RandHex(32))
	txHash3 := tktypes.MustParseBytes32(tktypes.RandHex(32))

	receipts := fmt.Sprintf(`{
		"receipts": [
			{"id": "%s", "success": true, "transactionHash": "%s"},
			{"id": "%s", "success": false, "transactionHash": "%s", "failureMessage": "tx failed"},
			{"id": "%s", "success": true, "transactionHash": "%s"}
		]
	}`, id1, txHash1, id2, txHash2, id3, txHash3)

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(tktypes.RawJSON(receipts))
	ack := notification.On("Ack", mock.Anything).Return(nil)
	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	opID1 := uuid.New()
	opID2 := uuid.New()
	opID3 := uuid.New()

	tx1 := &pldapi.TransactionFull{Transaction: &pldapi.Transaction{}}
	tx1.IdempotencyKey = fmt.Sprintf("ns1:%s", opID1)
	tx2 := &pldapi.TransactionFull{Transaction: &pldapi.Transaction{}}
	tx2.IdempotencyKey = fmt.Sprintf("ns1:%s", opID2)
	tx3 := &pldapi.TransactionFull{Transaction: &pldapi.Transaction{}}
	tx3.IdempotencyKey = fmt.Sprintf("ns2:%s", opID3)

	mockPTX.On("GetTransactionFull", mock.Anything, id1).Return(tx1, nil)
	mockPTX.On("GetTransactionFull", mock.Anything, id2).Return(tx2, nil)
	mockPTX.On("GetTransactionFull", mock.Anything, id3).Return(tx3, nil)

	em := &coremocks.OperationCallbacks{}
	bou := em.On("BulkOperationUpdates", mock.Anything, mock.Anything).Return(nil)
	bou.Run(func(args mock.Arguments) {
		updates := args.Get(1).([]*core.OperationUpdate)
		if assert.Len(t, updates, 2) {
			assert.Equal(t, "paladin", updates[0].Plugin)
			assert.Equal(t, fmt.Sprintf("ns1:%s", opID1), updates[0].NamespacedOpID)
			assert.Equal(t, core.OpStatusSucceeded, updates[0].Status)
			assert.Equal(t, txHash1.String(), updates[0].BlockchainTXID)
			assert.Empty(t, updates[0].ErrorMessage)

			assert.Equal(t, "paladin", updates[1].Plugin)
			assert.Equal(t, fmt.Sprintf("ns1:%s", opID2), updates[1].NamespacedOpID)
			assert.Equal(t, core.OpStatusFailed, updates[1].Status)
			assert.Equal(t, txHash2.String(), updates[1].BlockchainTXID)
			assert.Equal(t, "tx failed", updates[1].ErrorMessage)
		}
	})
	p.SetOperationHandler("ns1", em)

	done := make(chan bool, 1)
	ack.Run(func(args mock.Arguments) {
		done <- true
	})
	go p.batchEventLoop("ns1", sub)
	<-done
}

func TestBatchEventLoopDBWriteFail(t *testing.T) {
	p, _, mockPTX, _, cancel := NewTestPaladin(t)
	defer cancel()

	mockWSClient := paladinclientmocks.NewPaladinWSClient(t)
	mockWSClient.On("Close").Return().Maybe()
	p.wsconn["ns1"] = mockWSClient

	id := uuid.New()

	receipts := fmt.Sprintf(`{
		"receipts": [
			{"id": "%s", "success": true, "transactionHash": "%s"}
		]
	}`, id, tktypes.MustParseBytes32(tktypes.RandHex(32)))

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(tktypes.RawJSON(receipts))
	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	tx := &pldapi.TransactionFull{Transaction: &pldapi.Transaction{}}
	tx.IdempotencyKey = fmt.Sprintf("ns1:%s", uuid.New())
	mockPTX.On("GetTransactionFull", mock.Anything, id).Return(tx, nil)

	em := &coremocks.OperationCallbacks{}
	em.On("BulkOperationUpdates", mock.Anything, mock.Anything).Return(errors.New("db write err"))
	p.SetOperationHandler("ns1", em)

	// if we don't exit with an error this test will fail by timing out
	p.batchEventLoop("ns1", sub)
}

func TestBatchEventLoopAckFail(t *testing.T) {
	p, _, _, _, cancel := NewTestPaladin(t)
	defer cancel()

	mockWSClient := paladinclientmocks.NewPaladinWSClient(t)
	mockWSClient.On("Close").Return()
	p.wsconn["ns1"] = mockWSClient

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(tktypes.RawJSON(`{"receipts": []}`))
	err := paladinrpcclientmocks.NewErrorRPC(t)
	err.On("Error").Return("ack err")
	notification.On("Ack", mock.Anything).Return(err)
	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)
	// if we don't exit with an error this test will fail by timing out
	p.batchEventLoop("ns1", sub)
}

func TestBatchEventLoopErrorReadingSub(t *testing.T) {
	p, _, _, _, cancel := NewTestPaladin(t)
	defer cancel()

	mockWSClient := paladinclientmocks.NewPaladinWSClient(t)
	mockWSClient.On("Close").Return()
	p.wsconn["ns1"] = mockWSClient

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(tktypes.RawJSON(`{"receipts": []}`))
	c <- notification
	ack := notification.On("Ack", mock.Anything).Return(nil)
	ack.Run(func(args mock.Arguments) {
		close(c)
	})

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)
	p.batchEventLoop("ns1", sub)
}

func TestStopNamespace(t *testing.T) {
	p, _, mockPTX, ctx, _ := NewTestPaladin(t)

	wsClient := paladinclientmocks.NewPaladinWSClient(t)
	wsClient.On("Close").Return()
	p.wsconn["ns1"] = wsClient

	mockPTX.On("StopReceiptListener", mock.Anything, "ns1").Return(false, errors.New("stop rl err"))

	err := p.StopNamespace(ctx, "ns1")
	assert.NoError(t, err)
	assert.NotContains(t, p.wsconn, "ns1")

}

func TestResolveSigningKey(t *testing.T) {
	p, _, mockPTX, ctx, _ := NewTestPaladin(t)
	keyRef := "mykey"
	key := tktypes.MustEthAddress(tktypes.RandHex(20)).String()
	mockPTX.On("ResolveVerifier", mock.Anything, keyRef, "ecdsa:secp256k1", verifiers.ETH_ADDRESS).Return(key, nil)
	verifier, err := p.ResolveSigningKey(ctx, keyRef, blockchain.ResolveKeyIntentSign)
	require.NoError(t, err)
	assert.Equal(t, key, verifier)
}

func TestDeployContract(t *testing.T) {
	p, _, mockPTX, ctx, _ := NewTestPaladin(t)

	abiBytes, err := json.Marshal(contractABI)
	require.NoError(t, err)

	nsOpID := "ns1:9493d93e-9f88-4dd2-9173-ac42fdb6f748"
	signingKey := tktypes.MustEthAddress(tktypes.RandHex(20)).String()
	definition := fftypes.JSONAnyPtrBytes(abiBytes)
	contract := fftypes.JSONAnyPtr("\"0x1234\"")
	input := []interface{}{1, 2}
	options := map[string]interface{}{
		"gasLimit": "100000",
	}

	// bad byte code
	submissionRejected, err := p.DeployContract(ctx, nsOpID, signingKey, definition, nil, input, options)
	assert.Error(t, err)
	assert.True(t, submissionRejected)

	// bad ABI
	submissionRejected, err = p.DeployContract(ctx, nsOpID, signingKey, fftypes.JSONAnyPtr("thisisnotabi"), contract, input, options)
	assert.Error(t, err)
	assert.True(t, submissionRejected)

	// bad gas options
	submissionRejected, err = p.DeployContract(ctx, nsOpID, signingKey, definition, contract, input, map[string]interface{}{
		"gasLimit": "thisisnotanumber",
	})
	assert.Error(t, err)
	assert.True(t, submissionRejected)

	// successful submission
	st := mockPTX.On("SendTransaction", mock.Anything, mock.Anything).Return(nil, nil)
	st.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionInput)
		assert.Equal(t, nsOpID, tx.IdempotencyKey)
		assert.Equal(t, signingKey, tx.From)
		assert.Equal(t, pldapi.TransactionTypePublic.Enum(), tx.Type)
		assert.Equal(t, confutil.P(tktypes.MustParseHexUint64("100000")), tx.Gas)
		assert.Equal(t, tktypes.MustParseHexBytes("0x1234"), tx.Bytecode)
		assert.Equal(t, `[1,2]`, tx.Data.String())
		if assert.Len(t, tx.ABI, 2) {
			assert.Equal(t, get.Name, tx.ABI[0].Name)
			assert.Equal(t, set.Name, tx.ABI[1].Name)
		}
	})

	submissionRejected, err = p.DeployContract(ctx, nsOpID, signingKey, definition, contract, input, options)
	assert.NoError(t, err)
	assert.False(t, submissionRejected)
}

func TestValidateInvokeRequest(t *testing.T) {
	p, _, _, ctx, _ := NewTestPaladin(t)

	parsedMethod := &parsedFFIMethod{
		methodABI: set,
	}
	input := map[string]interface{}{
		"x": "1",
	}

	err := p.ValidateInvokeRequest(ctx, parsedMethod, input, false)
	assert.NoError(t, err)
}

func TestSetOptions(t *testing.T) {
	p, _, _, ctx, _ := NewTestPaladin(t)

	tx := &pldapi.TransactionInput{}
	err := p.setOptions(ctx, map[string]interface{}{
		"gasLimit":             "100000",
		"gasPrice":             "200000",
		"maxFeePerGas":         "300000",
		"maxPriorityFeePerGas": "400000",
		"value":                "500000",
	}, tx)
	require.NoError(t, err)
	assert.Equal(t, tktypes.MustParseHexUint64("100000"), *tx.Gas)
	assert.Equal(t, tktypes.MustParseHexUint256("200000"), tx.GasPrice)
	assert.Equal(t, tktypes.MustParseHexUint256("300000"), tx.MaxFeePerGas)
	assert.Equal(t, tktypes.MustParseHexUint256("400000"), tx.MaxPriorityFeePerGas)
	assert.Equal(t, tktypes.MustParseHexUint256("500000"), tx.Value)

	errTX := []struct {
		name    string
		options map[string]interface{}
	}{{
		name: "gasLimit",
		options: map[string]interface{}{
			"gasLimit": "notanumber",
		},
	}, {
		name: "gasPrice",
		options: map[string]interface{}{
			"gasPrice": "notanumber",
		},
	}, {
		name: "maxFeePerGas",
		options: map[string]interface{}{
			"maxFeePerGas": "notanumber",
		},
	}, {
		name: "maxPriorityFeePerGas",
		options: map[string]interface{}{
			"maxPriorityFeePerGas": "notanumber",
		},
	}, {
		name: "value",
		options: map[string]interface{}{
			"value": "notanumber",
		},
	}}
	for _, tt := range errTX {
		t.Run(tt.name, func(t *testing.T) {
			err := p.setOptions(ctx, tt.options, &pldapi.TransactionInput{})
			assert.Error(t, err)
		})
	}
}

func TestInvokeContract(t *testing.T) {
	p, _, mockPTX, ctx, _ := NewTestPaladin(t)

	nsOpID := "ns1:9493d93e-9f88-4dd2-9173-ac42fdb6f748"
	signingKey := tktypes.MustEthAddress(tktypes.RandHex(20)).String()
	contractAddress := tktypes.MustEthAddress(tktypes.RandHex(20)).String()
	//location := fftypes.JSONAnyPtr(fmt.Sprintf("\"%s\"", contractAddress))
	location := fftypes.JSONAnyPtr(fftypes.JSONObject{
		"address": contractAddress,
	}.String())
	parsedMethod := &parsedFFIMethod{
		methodABI: set,
	}
	input := map[string]interface{}{
		"x": 1,
	}
	options := map[string]interface{}{
		"gasLimit": "100000",
	}

	// invalid location
	submissionRejected, err := p.InvokeContract(ctx, nsOpID, signingKey, fftypes.JSONAnyPtr("notanethaddress"), parsedMethod, input, options, nil)
	assert.Error(t, err)
	assert.True(t, submissionRejected)

	// prepare fails
	invalidMethod := struct{}{}
	submissionRejected, err = p.InvokeContract(ctx, nsOpID, signingKey, location, invalidMethod, input, options, nil)
	assert.Error(t, err)
	assert.True(t, submissionRejected)

	// bad gas options
	submissionRejected, err = p.InvokeContract(ctx, nsOpID, signingKey, location, parsedMethod, input, map[string]interface{}{
		"gasLimit": "thisisnotanumber",
	}, nil)
	assert.Error(t, err)
	assert.True(t, submissionRejected)

	// successful submission
	st := mockPTX.On("SendTransaction", mock.Anything, mock.Anything).Return(nil, nil)
	st.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionInput)
		assert.Equal(t, nsOpID, tx.IdempotencyKey)
		assert.Equal(t, signingKey, tx.From)
		assert.Equal(t, pldapi.TransactionTypePublic.Enum(), tx.Type)
		assert.Equal(t, contractAddress, tx.To.String())
		assert.Equal(t, set.Name, tx.Function)
		assert.Equal(t, `{"x":1}`, tx.Data.String())
		if assert.Len(t, tx.ABI, 1) {
			assert.Equal(t, set.Name, tx.ABI[0].Name)
		}
	})
	submissionRejected, err = p.InvokeContract(ctx, nsOpID, signingKey, location, parsedMethod, input, options, nil)
	assert.NoError(t, err)
	assert.False(t, submissionRejected)
}

func TestQueryContract(t *testing.T) {
	p, _, mockPTX, ctx, _ := NewTestPaladin(t)

	signingKey := tktypes.MustEthAddress(tktypes.RandHex(20)).String()
	contractAddress := tktypes.MustEthAddress(tktypes.RandHex(20)).String()
	//location := fftypes.JSONAnyPtr(fmt.Sprintf("\"%s\"", contractAddress))
	location := fftypes.JSONAnyPtr(fftypes.JSONObject{
		"address": contractAddress,
	}.String())
	parsedMethod := &parsedFFIMethod{
		methodABI: get,
	}
	input := map[string]interface{}{
		"x": 1,
	}
	options := map[string]interface{}{
		"gasLimit": "100000",
	}

	// invalid location
	_, err := p.QueryContract(ctx, signingKey, fftypes.JSONAnyPtr("notanethaddress"), parsedMethod, input, options)
	assert.Error(t, err)

	// prepare fails
	invalidMethod := struct{}{}
	_, err = p.QueryContract(ctx, signingKey, location, invalidMethod, input, options)
	assert.Error(t, err)

	// bad gas options
	_, err = p.QueryContract(ctx, signingKey, location, parsedMethod, input, map[string]interface{}{
		"gasLimit": "thisisnotanumber",
	})
	assert.Error(t, err)

	// successful submission
	call := mockPTX.On("Call", mock.Anything, mock.Anything).Return(tktypes.RawJSON(`{"retValue": 4}`), nil)
	call.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionCall)
		assert.Equal(t, signingKey, tx.From)
		assert.Equal(t, pldapi.TransactionTypePublic.Enum(), tx.Type)
		assert.Equal(t, contractAddress, tx.To.String())
		assert.Equal(t, get.Name, tx.Function)
		assert.Equal(t, `{"x":1}`, tx.Data.String())
		if assert.Len(t, tx.ABI, 1) {
			assert.Equal(t, get.Name, tx.ABI[0].Name)
		}
	})
	result, err := p.QueryContract(ctx, signingKey, location, parsedMethod, input, options)
	assert.NoError(t, err)
	assert.Equal(t, tktypes.RawJSON(`{"retValue": 4}`), result)
}

func TestGetTransactionStatus(t *testing.T) {
	p, _, mockPTX, ctx, _ := NewTestPaladin(t)

	id := fftypes.NewUUID()
	op := &core.Operation{
		ID:        id,
		Namespace: "ns1",
	}

	// paladin error
	mockPTX.On("QueryTransactionsFull", mock.Anything, mock.Anything).Return(nil, errors.New("paladin error")).Once()
	_, err := p.GetTransactionStatus(ctx, op)
	assert.Regexp(t, "FF10483.*paladin error", err)

	// no match
	mockPTX.On("QueryTransactionsFull", mock.Anything, mock.Anything).Return([]*pldapi.TransactionFull{}, nil).Once()
	tx, err := p.GetTransactionStatus(ctx, op)
	assert.NoError(t, err)
	assert.Nil(t, tx)

	// match
	qt := mockPTX.On("QueryTransactionsFull", mock.Anything, mock.Anything).Return([]*pldapi.TransactionFull{{
		Transaction: &pldapi.Transaction{
			TransactionBase: pldapi.TransactionBase{
				IdempotencyKey: fmt.Sprintf("ns1:%s", id),
			},
		},
	}}, nil).Once()
	qt.Run(func(args mock.Arguments) {
		filter := args.Get(1).(*query.QueryJSON)
		assert.Equal(t, 1, *filter.Limit)
		if assert.Len(t, filter.Statements.Ops.Eq, 1) {
			assert.Equal(t, &query.OpSingleVal{
				Op: query.Op{
					Field: "idempotencyKey",
				},
				Value: tktypes.JSONString(fmt.Sprintf("ns1:%s", id)),
			}, filter.Statements.Ops.Eq[0])
		}
	})
	tx, err = p.GetTransactionStatus(ctx, op)
	require.NoError(t, err)
	require.NotNil(t, tx)
}

func TestParseInterface(t *testing.T) {
	p, _, _, ctx, _ := NewTestPaladin(t)

	badSchema := fftypes.JSONAnyPtr("{badschema}")
	goodSchema := fftypes.JSONAnyPtr(`{"oneOf":[{"type":"string"},{"type":"integer"}],"details":{"type":"uint256"}}`)

	method := &fftypes.FFIMethod{
		Params: fftypes.FFIParams{{
			Name: "x",
		}},
	}
	errors := []*fftypes.FFIError{{
		FFIErrorDefinition: fftypes.FFIErrorDefinition{
			Params: fftypes.FFIParams{{
				Name: "err",
			}},
		},
	}}

	// bad method
	method.Params[0].Schema = badSchema
	_, err := p.ParseInterface(ctx, method, errors)
	assert.ErrorContains(t, err, "FF22052")

	// bad error
	method.Params[0].Schema = goodSchema
	errors[0].Params[0].Schema = badSchema
	_, err = p.ParseInterface(ctx, method, errors)
	assert.ErrorContains(t, err, "FF22052")

	// success
	errors[0].Params[0].Schema = goodSchema
	methodInfo, err := p.ParseInterface(ctx, method, errors)
	require.NoError(t, err)
	parsedMethod := methodInfo.(*parsedFFIMethod)
	assert.Equal(t, "x", parsedMethod.methodABI.Inputs[0].Name)
	assert.Equal(t, "err", parsedMethod.errorsABI[0].Inputs[0].Name)
}

func TestSetHandler(t *testing.T) {
	p, _, _, _, _ := NewTestPaladin(t)
	p.SetHandler("ns1", &blockchainmocks.Callbacks{})
}

func TestGetFFIParamValidator(t *testing.T) {
	p, _, _, ctx, _ := NewTestPaladin(t)

	validator, err := p.GetFFIParamValidator(ctx)
	require.NoError(t, err)
	assert.Implements(t, (*fftypes.FFIParamValidator)(nil), validator)
}

func TestGenerateFFI(t *testing.T) {
	p, _, _, ctx, _ := NewTestPaladin(t)

	_, err := p.GenerateFFI(ctx, &fftypes.FFIGenerationRequest{
		Name:        "Simple",
		Version:     "v0.0.1",
		Description: "desc",
		Input:       fftypes.JSONAnyPtr(`{"abi": [{}]}`),
	})
	assert.NoError(t, err)

	// inline namespace
	ffi, err := p.GenerateFFI(ctx, &fftypes.FFIGenerationRequest{
		Name:        "Simple",
		Version:     "v0.0.1",
		Description: "desc",
		Namespace:   "ns1",
		Input:       fftypes.JSONAnyPtr(`{"abi":[{}]}`),
	})
	assert.NoError(t, err)
	assert.Equal(t, ffi.Namespace, "ns1")

	// empty ABI
	_, err = p.GenerateFFI(ctx, &fftypes.FFIGenerationRequest{
		Name:        "Simple",
		Version:     "v0.0.1",
		Description: "desc",
		Input:       fftypes.JSONAnyPtr(`{"abi": []}`),
	})
	assert.Regexp(t, "FF10346", err)

	// bad ABI
	_, err = p.GenerateFFI(ctx, &fftypes.FFIGenerationRequest{
		Name:        "Simple",
		Version:     "v0.0.1",
		Description: "desc",
		Input:       fftypes.JSONAnyPtr(`{"abi": "not an array"}`),
	})
	assert.Regexp(t, "FF10346", err)
}

func TestNormalizeContractLocation(t *testing.T) {
	p, _, _, ctx, _ := NewTestPaladin(t)

	// invalid JSON
	locationBytes := []byte("bad")
	_, err := p.NormalizeContractLocation(ctx, blockchain.NormalizeCall, fftypes.JSONAnyPtrBytes(locationBytes))
	assert.Regexp(t, "FF10310", err)

	// invalid location
	locationBytes, _ = json.Marshal(&Location{
		Address: "bad",
	})
	_, err = p.NormalizeContractLocation(ctx, blockchain.NormalizeCall, fftypes.JSONAnyPtrBytes(locationBytes))
	assert.Regexp(t, "FF10141", err)

	// valid location
	locationBytes, _ = json.Marshal(&Location{
		Address: "3081D84FD367044F4ED453F2024709242470388C",
	})
	result, err := p.NormalizeContractLocation(ctx, blockchain.NormalizeCall, fftypes.JSONAnyPtrBytes(locationBytes))
	require.NoError(t, err)
	assert.Equal(t, "0x3081d84fd367044f4ed453f2024709242470388c", result.JSONObject()["address"])

	// blank
	locationBytes, _ = json.Marshal(&Location{})
	_, err = p.NormalizeContractLocation(ctx, blockchain.NormalizeCall, fftypes.JSONAnyPtrBytes(locationBytes))
	assert.Regexp(t, "FF10310", err)
}

func TestNoops(t *testing.T) {
	p, _, _, ctx, _ := NewTestPaladin(t)

	err := p.SubmitBatchPin(ctx, "", "", "", nil, nil)
	assert.NoError(t, err)

	err = p.SubmitNetworkAction(ctx, "", "", "", nil)
	assert.NoError(t, err)

	err = p.AddContractListener(ctx, nil, "")
	assert.NoError(t, err)

	err = p.DeleteContractListener(ctx, nil, false)
	assert.NoError(t, err)

	_, _, _, err = p.GetContractListenerStatus(ctx, "", "", false)
	assert.NoError(t, err)

	_, err = p.GenerateEventSignature(ctx, nil)
	assert.NoError(t, err)

	_, err = p.GenerateEventSignatureWithLocation(ctx, nil, nil)
	assert.NoError(t, err)

	_, err = p.CheckOverlappingLocations(ctx, nil, nil)
	assert.NoError(t, err)

	sig := p.GenerateErrorSignature(ctx, nil)
	assert.Empty(t, sig)

	_, err = p.GetNetworkVersion(ctx, nil)
	assert.NoError(t, err)

	_, _, err = p.GetAndConvertDeprecatedContractConfig(ctx)
	assert.NoError(t, err)

	_, err = p.AddFireflySubscription(ctx, nil, nil, "")
	assert.NoError(t, err)

	p.RemoveFireflySubscription(ctx, "")
	// no return values to assert on
}
