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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/fftls"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly/internal/blockchain/common"
	"github.com/hyperledger/firefly/internal/cache"
	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/mocks/blockchaincommonmocks"
	"github.com/hyperledger/firefly/mocks/blockchainmocks"
	"github.com/hyperledger/firefly/mocks/cachemocks"
	"github.com/hyperledger/firefly/mocks/coremocks"
	"github.com/hyperledger/firefly/mocks/metricsmocks"
	"github.com/hyperledger/firefly/mocks/paladinclientmocks"
	"github.com/hyperledger/firefly/mocks/paladinrpcclientmocks"
	"github.com/hyperledger/firefly/pkg/blockchain"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/sdk/go/pkg/pldapi"
	"github.com/kaleido-io/paladin/sdk/go/pkg/pldclient"
	"github.com/kaleido-io/paladin/sdk/go/pkg/pldtypes"
	"github.com/kaleido-io/paladin/sdk/go/pkg/query"
	"github.com/kaleido-io/paladin/sdk/go/pkg/rpcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var utConfig = config.RootSection("paladin_unit_tests")
var utRPCConfig = utConfig.SubSection(PaladinRPCClientConfigKey)
var utAddressResolverConf = utConfig.SubSection(AddressResolverConfigKey)

var get = &abi.Entry{
	Name: "get",
	Inputs: abi.ParameterArray{{
		Name:         "x",
		Type:         "uint256",
		InternalType: "uint256",
	}},
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

type paladinMocks struct {
	paladinClient *paladinclientmocks.PaladinClient
	ptx           *paladinclientmocks.PTX
	callbacks     *blockchaincommonmocks.BlockchainCallbacks
	subs          *blockchaincommonmocks.FireflySubscriptions
}

func newTestPaladin(t *testing.T) (*Paladin, *paladinMocks, context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	mm := &metricsmocks.Manager{}
	mm.On("IsMetricsEnabled").Return(true)
	mm.On("BlockchainTransaction", mock.Anything, mock.Anything).Return(nil)
	mm.On("BlockchainContractDeployment", mock.Anything, mock.Anything).Return(nil)
	mm.On("BlockchainQuery", mock.Anything, mock.Anything).Return(nil)
	p := &Paladin{
		ctx:        ctx,
		cancelCtx:  cancel,
		metrics:    mm,
		wsconn:     make(map[string]pldclient.PaladinWSClient),
		cache:      cache.NewUmanagedCache(ctx, 100, 5*time.Minute),
		eventLoops: make(map[string]context.CancelFunc),
	}

	mockPaladinClient := paladinclientmocks.NewPaladinClient(t)
	mockPTX := paladinclientmocks.NewPTX(t)

	mockPaladinClient.On("PTX").Return(mockPTX).Maybe()

	p.httpClient = mockPaladinClient
	p.pldClient = mockPaladinClient

	wsClient := paladinclientmocks.NewPaladinWSClient(t)
	wsClient.On("Close").Return().Maybe()
	wsClient.On("PTX").Return(mockPTX).Maybe()
	p.wsconn["ns1"] = wsClient

	mockCallbacks := blockchaincommonmocks.NewBlockchainCallbacks(t)
	p.callbacks = mockCallbacks

	mockSubs := blockchaincommonmocks.NewFireflySubscriptions(t)
	p.subs = mockSubs

	return p, &paladinMocks{
		paladinClient: mockPaladinClient,
		ptx:           mockPTX,
		callbacks:     mockCallbacks,
		subs:          mockSubs,
	}, ctx, cancel
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

func TestInitCacheFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Paladin{}
	resetConf(p)
	utRPCConfig.Set("url", "https://localhost:1234")
	utRPCConfig.Set("ws.url", "ws://localhost:1234")
	mm := &metricsmocks.Manager{}
	cm := &cachemocks.Manager{}
	cm.On("GetCache", mock.Anything).Return(nil, errors.New("cache error"))

	err := p.Init(ctx, cancel, utConfig, mm, cm)
	assert.EqualError(t, err, "cache error")
}

func TestInitAddressResolverFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Paladin{}
	resetConf(p)
	utRPCConfig.Set("url", "https://localhost:1234")
	utRPCConfig.Set("ws.url", "ws://localhost:1234")
	mm := &metricsmocks.Manager{}
	cm := &cachemocks.Manager{}
	cm.On("GetCache", mock.Anything).Return(cache.NewUmanagedCache(p.ctx, 100, 5*time.Minute), nil)
	utAddressResolverConf.Set(AddressResolverEnable, true)
	utAddressResolverConf.Set(AddressResolverURLTemplate, "{{unclosed}")

	err := p.Init(ctx, cancel, utConfig, mm, cm)
	assert.Regexp(t, "FF10337", err)
}

func TestInitSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Paladin{}
	resetConf(p)
	utRPCConfig.Set("url", "https://localhost:1234")
	utRPCConfig.Set("ws.url", "ws://localhost:1234")
	mm := &metricsmocks.Manager{}
	cm := &cachemocks.Manager{}
	cm.On("GetCache", mock.Anything).Return(cache.NewUmanagedCache(p.ctx, 100, 5*time.Minute), nil)

	err := p.Init(ctx, cancel, utConfig, mm, cm)

	require.NoError(t, err)
	assert.Equal(t, mm, p.metrics)
	assert.NotNil(t, p.Capabilities())
}

func TestName(t *testing.T) {
	p, _, _, _ := newTestPaladin(t)
	assert.Equal(t, "paladin", p.Name())
}

func TestVerifierType(t *testing.T) {
	p, _, _, _ := newTestPaladin(t)
	assert.Equal(t, core.VerifierTypeEthAddress, p.VerifierType())
}

func TestStartNamespace(t *testing.T) {
	p, mocks, ctx, cancel := newTestPaladin(t)
	defer cancel()

	mockWSPTX := paladinclientmocks.NewPTX(t)
	mockWS := paladinclientmocks.NewPaladinWSClient(t)
	mockWS.On("PTX").Return(mockWSPTX).Maybe()
	mockWS.On("Close").Return().Maybe()

	// error starting receipt listener
	mocks.ptx.On("StartReceiptListener", mock.Anything, "ns1").Return(false, errors.New("start rl err")).Once()
	err := p.StartNamespace(ctx, "ns1")
	assert.ErrorContains(t, err, "start rl err")

	// error creating receipt listener
	mocks.ptx.On("StartReceiptListener", mock.Anything, "ns1").Return(false, errors.New("PD012238")).Once()
	mocks.ptx.On("CreateReceiptListener", mock.Anything, &pldapi.TransactionReceiptListener{
		Name: "ns1",
	}).Return(false, errors.New("create rl err")).Once()
	err = p.StartNamespace(ctx, "ns1")
	assert.ErrorContains(t, err, "create rl err")

	// error starting websocket
	mocks.ptx.On("StartReceiptListener", mock.Anything, "ns1").Return(true, nil)
	mocks.paladinClient.On("WebSocket", mock.Anything, mock.Anything).Return(nil, errors.New("start ws err")).Once()
	err = p.StartNamespace(ctx, "ns1")
	assert.ErrorContains(t, err, "start ws err")

	// error subscribing to receipts
	mocks.paladinClient.On("WebSocket", mock.Anything, mock.Anything).Return(mockWS, nil)
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

func TestBatchEventLoopErrorUnmarshallingFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := log.L(ctx)
	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{"receipts": 4}`))
	nack := notification.On("Nack", mock.Anything).Return(nil)

	nacked := make(chan bool, 1)
	nack.Run(func(args mock.Arguments) {
		nacked <- true
	})

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	go batchEventLoop(ctx, l, cancel, sub, func(batch *pldapi.TransactionReceiptBatch) error {
		return nil
	})
	<-nacked
}

func TestBatchEventLoopErrorUnmarshallingNackFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := log.L(ctx)
	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{"receipts": 4}`))
	err := paladinrpcclientmocks.NewErrorRPC(t)
	err.On("Error").Return("nack err")
	notification.On("Nack", mock.Anything).Return(err)

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	// if we don't exit with an error this test will fail by timing out
	batchEventLoop(ctx, l, cancel, sub, func(batch *pldapi.TransactionReceiptBatch) error {
		return nil
	})
}

func TestBatchEventLoopErrorHandlerFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := log.L(ctx)
	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{}`))
	nack := notification.On("Nack", mock.Anything).Return(nil)

	nacked := make(chan bool, 1)
	nack.Run(func(args mock.Arguments) {
		nacked <- true
	})

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	go batchEventLoop(ctx, l, cancel, sub, func(batch *pldapi.TransactionReceiptBatch) error {
		return errors.New("handler err")
	})
	<-nacked
}

func TestBatchEventLoopErrorHandlerNackFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := log.L(ctx)
	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{}`))
	err := paladinrpcclientmocks.NewErrorRPC(t)
	err.On("Error").Return("nack err")
	notification.On("Nack", mock.Anything).Return(err)

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	// if we don't exit with an error this test will fail by timing out
	batchEventLoop(ctx, l, cancel, sub, func(batch *pldapi.TransactionReceiptBatch) error {
		return errors.New("handler err")
	})
}

func TestBatchEventLoopErrorAckFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := log.L(ctx)
	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{}`))
	err := paladinrpcclientmocks.NewErrorRPC(t)
	err.On("Error").Return("ack err")
	notification.On("Ack", mock.Anything).Return(err)

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	// if we don't exit with an error this test will fail by timing out
	batchEventLoop(ctx, l, cancel, sub, func(batch *pldapi.TransactionReceiptBatch) error {
		return nil
	})
}

func TestBatchEventLoopErrorReadingSub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := log.L(ctx)
	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{}`))
	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification
	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)
	ack := notification.On("Ack", mock.Anything).Return(nil)
	ack.Run(func(args mock.Arguments) {
		close(c)
	})

	// if we don't exit with an error this test will fail by timing out
	batchEventLoop(ctx, l, cancel, sub, func(batch *pldapi.TransactionReceiptBatch) error {
		return nil
	})
}

func TestReceiptEventLoopErrorFetchingTransaction(t *testing.T) {
	p, mocks, _, cancel := newTestPaladin(t)
	defer cancel()

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{"receipts": [{"id": "c920c994-8beb-49a8-9141-48f0fa61b050"}]}`))
	nack := notification.On("Nack", mock.Anything).Return(nil)
	nacked := make(chan bool, 1)
	nack.Run(func(args mock.Arguments) {
		nacked <- true
	})

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	mocks.ptx.On("GetTransactionFull", mock.Anything, uuid.MustParse("c920c994-8beb-49a8-9141-48f0fa61b050")).
		Return(nil, errors.New("get tx err"))
	p.receiptEventLoop("ns1", sub)
	<-nacked
}

func TestReceiptEventLoopSuccess(t *testing.T) {
	p, mocks, _, cancel := newTestPaladin(t)
	defer cancel()

	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()
	txHash1 := pldtypes.MustParseBytes32(pldtypes.RandHex(32))
	txHash2 := pldtypes.MustParseBytes32(pldtypes.RandHex(32))
	txHash3 := pldtypes.MustParseBytes32(pldtypes.RandHex(32))

	receipts := fmt.Sprintf(`{
		"receipts": [
			{"id": "%s", "success": true, "transactionHash": "%s"},
			{"id": "%s", "success": false, "transactionHash": "%s", "failureMessage": "tx failed"},
			{"id": "%s", "success": true, "transactionHash": "%s"}
		]
	}`, id1, txHash1, id2, txHash2, id3, txHash3)

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(receipts))
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

	mocks.ptx.On("GetTransactionFull", mock.Anything, id1).Return(tx1, nil)
	mocks.ptx.On("GetTransactionFull", mock.Anything, id2).Return(tx2, nil)
	mocks.ptx.On("GetTransactionFull", mock.Anything, id3).Return(tx3, nil)

	bou := mocks.callbacks.On("BulkOperationUpdates", mock.Anything, "ns1", mock.Anything).Return(nil)
	bou.Run(func(args mock.Arguments) {
		updates := args.Get(2).([]*core.OperationUpdate)
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

	done := make(chan bool, 1)
	ack.Run(func(args mock.Arguments) {
		done <- true
	})
	p.receiptEventLoop("ns1", sub)
	<-done
}

func TestReceiptEventLoopDBWriteFail(t *testing.T) {
	p, mocks, _, cancel := newTestPaladin(t)
	defer cancel()

	id := uuid.New()

	receipts := fmt.Sprintf(`{
		"receipts": [
			{"id": "%s", "success": true, "transactionHash": "%s"}
		]
	}`, id, pldtypes.MustParseBytes32(pldtypes.RandHex(32)))

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(receipts))
	nack := notification.On("Nack", mock.Anything).Return(nil)
	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	tx := &pldapi.TransactionFull{Transaction: &pldapi.Transaction{}}
	tx.IdempotencyKey = fmt.Sprintf("ns1:%s", uuid.New())
	mocks.ptx.On("GetTransactionFull", mock.Anything, id).Return(tx, nil)
	mocks.callbacks.On("BulkOperationUpdates", mock.Anything, "ns1", mock.Anything).Return(errors.New("db write err"))

	done := make(chan bool, 1)
	nack.Run(func(args mock.Arguments) {
		done <- true
	})
	p.receiptEventLoop("ns1", sub)
	<-done
}

func TestReceiptEventLoopCancelCalled(t *testing.T) {
	p, _, _, _ := newTestPaladin(t)

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(`{"receipts": 4}`))

	err := paladinrpcclientmocks.NewErrorRPC(t)
	err.On("Error").Return("nack err")
	notification.On("Nack", mock.Anything).Return(err)

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	c <- notification

	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	p.receiptEventLoop("ns1", sub)
	<-p.ctx.Done()
}

func TestStopNamespace(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)

	mocks.ptx.On("StopReceiptListener", mock.Anything, "ns1").Return(false, errors.New("stop rl err"))

	err := p.StopNamespace(ctx, "ns1")
	assert.NoError(t, err)
	assert.NotContains(t, p.wsconn, "ns1")
}

func TestSetHandler(t *testing.T) {
	p, mocks, _, _ := newTestPaladin(t)
	mocks.callbacks.On("SetHandler", "ns1", mock.Anything).Return(nil)
	p.SetHandler("ns1", &blockchainmocks.Callbacks{})
}

func TestSetOperationHandler(t *testing.T) {
	p, mocks, _, _ := newTestPaladin(t)
	mocks.callbacks.On("SetOperationalHandler", "ns1", mock.Anything).Return(nil)
	p.SetOperationHandler("ns1", coremocks.NewOperationCallbacks(t))
}

func TestResolveSigningKeyNoKey(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	// query - allowed
	verifier, err := p.ResolveSigningKey(ctx, "", blockchain.ResolveKeyIntentQuery)
	require.NoError(t, err)
	assert.Equal(t, "", verifier)

	// not query- error
	verifier, err = p.ResolveSigningKey(ctx, "", blockchain.ResolveKeyIntentSign)
	require.Error(t, err)
}

func TestResolveSigningKeyAddressResolver(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)
	p.addressResolver = &addressResolver{}

	// eth address doesn't need resolving
	key := pldtypes.RandAddress().String()
	verifier, err := p.ResolveSigningKey(ctx, key, blockchain.ResolveKeyIntentSign)
	require.NoError(t, err)
	assert.Equal(t, key, verifier)

	// error in address resolver
	keyRef := "mykey"
	p.addressResolver.urlTemplate, err = template.New(AddressResolverURLTemplate).Option("missingkey=error").Parse("http://ff.example/resolve/{{.Wrong}}")
	require.NoError(t, err)
	verifier, err = p.ResolveSigningKey(ctx, keyRef, blockchain.ResolveKeyIntentSign)
	require.ErrorContains(t, err, "FF10338")

	// address resolver success
	p.addressResolver.cache = cache.NewUmanagedCache(p.ctx, 100, 5*time.Minute)
	p.addressResolver.cache.Set(keyRef, key)
	verifier, err = p.ResolveSigningKey(ctx, keyRef, blockchain.ResolveKeyIntentSign)
	require.NoError(t, err)
	assert.Equal(t, key, verifier)

}

func TestResolveSigningKeyCallPaladin(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)
	keyRef := "mykey"
	key := pldtypes.RandAddress().String()

	// eth address doesn't need resolving
	verifier, err := p.ResolveSigningKey(ctx, key, blockchain.ResolveKeyIntentSign)
	require.NoError(t, err)
	assert.Equal(t, key, verifier)

	mocks.ptx.On("ResolveVerifier", mock.Anything, keyRef, "ecdsa:secp256k1", "eth_address").Return(key, nil)
	verifier, err = p.ResolveSigningKey(ctx, keyRef, blockchain.ResolveKeyIntentSign)
	require.NoError(t, err)
	assert.Equal(t, key, verifier)
}

func TestDeployContract(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)

	abiBytes, err := json.Marshal(contractABI)
	require.NoError(t, err)

	nsOpID := "ns1:9493d93e-9f88-4dd2-9173-ac42fdb6f748"
	signingKey := pldtypes.MustEthAddress(pldtypes.RandHex(20)).String()
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
	st := mocks.ptx.On("SendTransaction", mock.Anything, mock.Anything).Return(nil, nil)
	st.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionInput)
		assert.Equal(t, nsOpID, tx.IdempotencyKey)
		assert.Equal(t, signingKey, tx.From)
		assert.Equal(t, pldapi.TransactionTypePublic.Enum(), tx.Type)
		assert.Equal(t, confutil.P(pldtypes.MustParseHexUint64("100000")), tx.Gas)
		assert.Equal(t, pldtypes.MustParseHexBytes("0x1234"), tx.Bytecode)
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
	p, _, ctx, _ := newTestPaladin(t)

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
	p, _, ctx, _ := newTestPaladin(t)

	tx := &pldapi.TransactionInput{}
	err := p.setOptions(ctx, map[string]interface{}{
		"gasLimit":             "100000",
		"gasPrice":             "200000",
		"maxFeePerGas":         "300000",
		"maxPriorityFeePerGas": "400000",
		"value":                "500000",
	}, tx)
	require.NoError(t, err)
	assert.Equal(t, pldtypes.MustParseHexUint64("100000"), *tx.Gas)
	assert.Equal(t, pldtypes.MustParseHexUint256("200000"), tx.GasPrice)
	assert.Equal(t, pldtypes.MustParseHexUint256("300000"), tx.MaxFeePerGas)
	assert.Equal(t, pldtypes.MustParseHexUint256("400000"), tx.MaxPriorityFeePerGas)
	assert.Equal(t, pldtypes.MustParseHexUint256("500000"), tx.Value)

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
	p, mocks, ctx, _ := newTestPaladin(t)

	nsOpID := "ns1:9493d93e-9f88-4dd2-9173-ac42fdb6f748"
	signingKey := pldtypes.MustEthAddress(pldtypes.RandHex(20)).String()
	contractAddress := pldtypes.MustEthAddress(pldtypes.RandHex(20)).String()
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

	// invalid address
	badAddress := fftypes.JSONAnyPtr(fftypes.JSONObject{
		"address": "thisIsNotAnAddress",
	}.String())
	_, err = p.InvokeContract(ctx, nsOpID, signingKey, badAddress, parsedMethod, input, options, nil)
	assert.Error(t, err)

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
	st := mocks.ptx.On("SendTransaction", mock.Anything, mock.Anything).Return(nil, nil).Once()
	st.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionInput)
		assert.Equal(t, nsOpID, tx.IdempotencyKey)
		assert.Equal(t, signingKey, tx.From)
		assert.Equal(t, pldapi.TransactionTypePublic.Enum(), tx.Type)
		assert.Equal(t, contractAddress, tx.To.String())
		assert.Equal(t, set.Name, tx.Function)
		assert.Equal(t, `[1]`, tx.Data.String())
		if assert.Len(t, tx.ABI, 1) {
			assert.Equal(t, set.Name, tx.ABI[0].Name)
		}
	})
	submissionRejected, err = p.InvokeContract(ctx, nsOpID, signingKey, location, parsedMethod, input, options, nil)
	assert.NoError(t, err)
	assert.False(t, submissionRejected)

	// batch pin- no data support
	submissionRejected, err = p.InvokeContract(ctx, nsOpID, signingKey, location, parsedMethod, input, nil, &blockchain.BatchPin{})
	assert.Error(t, err)
	assert.True(t, submissionRejected)

	// batch pin success
	mocks.ptx.On("SendTransaction", mock.Anything, mock.Anything).Return(nil, nil).Once()
	parsedBatchPinMethod := &parsedFFIMethod{
		methodABI: &abi.Entry{
			Inputs: abi.ParameterArray{
				{
					Type: "bytes",
				},
			},
		},
	}
	submissionRejected, err = p.InvokeContract(ctx, nsOpID, signingKey, location, parsedBatchPinMethod, input, nil, &blockchain.BatchPin{
		Contexts:        []*fftypes.Bytes32{fftypes.NewRandB32()},
		TransactionID:   fftypes.NewUUID(),
		BatchID:         fftypes.NewUUID(),
		BatchHash:       fftypes.NewRandB32(),
		BatchPayloadRef: "ref",
	})
	assert.NoError(t, err)
	assert.False(t, submissionRejected)
}

func TestQueryContract(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)

	signingKey := pldtypes.MustEthAddress(pldtypes.RandHex(20)).String()
	contractAddress := pldtypes.MustEthAddress(pldtypes.RandHex(20)).String()
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

	// invalid address
	badAddress := fftypes.JSONAnyPtr(fftypes.JSONObject{
		"address": "thisIsNotAnAddress",
	}.String())
	_, err = p.QueryContract(ctx, signingKey, badAddress, parsedMethod, input, options)
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

	// successful submission - number blockNumber
	call := mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(pldtypes.RawJSON(`{"retValue": 4}`), nil).Once()
	call.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionCall)
		assert.Equal(t, signingKey, tx.From)
		assert.Equal(t, pldapi.TransactionTypePublic.Enum(), tx.Type)
		assert.Equal(t, contractAddress, tx.To.String())
		assert.Equal(t, get.Name, tx.Function)
		assert.Equal(t, `[1]`, tx.Data.String())
		if assert.Len(t, tx.ABI, 1) {
			assert.Equal(t, get.Name, tx.ABI[0].Name)
		}
		assert.Equal(t, "0x1", tx.Block.String())
	})
	result, err := p.QueryContract(ctx, signingKey, location, parsedMethod, input, map[string]interface{}{
		"blockNumber": json.Number("1"),
	})
	assert.NoError(t, err)
	assert.Equal(t, pldtypes.RawJSON(`{"retValue": 4}`), result)

	// successful submission - string blockNumber
	call = mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(pldtypes.RawJSON(`{"retValue": 4}`), nil).Once()
	call.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionCall)
		assert.Equal(t, "latest", tx.Block.String())
	})
	result, err = p.QueryContract(ctx, signingKey, location, parsedMethod, input, map[string]interface{}{
		"blockNumber": "latest",
	})
	assert.NoError(t, err)
	assert.Equal(t, pldtypes.RawJSON(`{"retValue": 4}`), result)
}

func TestAddContractListener(t *testing.T) {
	p, mocks, ctx, cancel := newTestPaladin(t)
	defer cancel()

	// invalid param
	listener := &core.ContractListener{
		ID:        fftypes.NewUUID(),
		Namespace: "ns1",
		Filters: core.ListenerFilters{{
			Event: &core.FFISerializedEvent{
				FFIEventDefinition: fftypes.FFIEventDefinition{
					Params: fftypes.FFIParams{{
						Name:   "a",
						Schema: fftypes.JSONAnyPtr(`{"type":"string"`),
					}},
				},
			},
		}},
	}
	err := p.AddContractListener(ctx, listener, "")
	require.ErrorContains(t, err, "FF10311")

	// invalid source address
	listener.Filters = core.ListenerFilters{{
		Location: fftypes.JSONAnyPtr(`{"address":"foo"}`),
		Event: &core.FFISerializedEvent{
			FFIEventDefinition: fftypes.FFIEventDefinition{
				Name: "event1",
			},
		},
	}}
	err = p.AddContractListener(ctx, listener, "")
	require.ErrorContains(t, err, "FF10141")

	// invalid from block
	addr := pldtypes.RandAddress().String()
	listener.Filters[0].Location = fftypes.JSONAnyPtr(fmt.Sprintf(`{"address":"%s"}`, addr))
	listener.Options = &core.ContractListenerOptions{
		FirstEvent: "banana",
	}
	err = p.AddContractListener(ctx, listener, "")
	require.ErrorContains(t, err, "FF10473")

	// fail to create listener
	listener.Options.FirstEvent = "latest"
	mocks.ptx.On("CreateBlockchainEventListener", mock.Anything, mock.Anything).Return(false, errors.New("paladin error")).Once()
	err = p.AddContractListener(ctx, listener, "")
	require.ErrorContains(t, err, "FF10483")

	// fail to subscribe
	mocks.ptx.On("CreateBlockchainEventListener", mock.Anything, mock.Anything).Return(true, nil).Once()
	mocks.ptx.On("SubscribeBlockchainEvents", mock.Anything, mock.Anything).Return(nil, errors.New("paladin error")).Once()
	err = p.AddContractListener(ctx, listener, "")
	require.ErrorContains(t, err, "FF10483")

	// success
	create := mocks.ptx.On("CreateBlockchainEventListener", mock.Anything, mock.Anything).Return(true, nil).Once()
	create.Run(func(args mock.Arguments) {
		bel := args.Get(1).(*pldapi.BlockchainEventListener)
		assert.Equal(t, fmt.Sprintf("ff-listener-%s", listener.ID.String()), bel.Name)
		if assert.Len(t, bel.Sources, 1) {
			assert.Equal(t, addr, bel.Sources[0].Address.String())
			if assert.Len(t, bel.Sources[0].ABI, 1) {
				assert.Equal(t, "event1", bel.Sources[0].ABI[0].Name)
			}
		}
		assert.Equal(t, json.RawMessage("\"latest\""), bel.Options.FromBlock)
	})
	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(make(chan rpcclient.RPCSubscriptionNotification, 1)).Maybe()
	mocks.ptx.On("SubscribeBlockchainEvents", mock.Anything, fmt.Sprintf("ff-listener-%s", listener.ID.String())).Return(sub, nil)

	err = p.AddContractListener(ctx, listener, "")
	require.NoError(t, err)
}

func TestDeleteContractListener(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)

	listenerID := fftypes.NewUUID()
	paladinListenerName := fmt.Sprintf("ff-listener-%s", listenerID.String())

	// error calling delete
	mocks.ptx.On("DeleteBlockchainEventListener", mock.Anything, paladinListenerName).Return(false, errors.New("PD012248 Not Found")).Twice()
	err := p.DeleteContractListener(ctx, &core.ContractListener{
		ID: listenerID,
	}, false)
	require.ErrorContains(t, err, "PD012248")

	// not found calling delete but allowed
	err = p.DeleteContractListener(ctx, &core.ContractListener{
		ID: listenerID,
	}, true)
	require.NoError(t, err)

	// successful delete
	ctx, cancel := context.WithCancel(ctx)
	p.eventLoops[listenerID.String()] = cancel
	mocks.ptx.On("DeleteBlockchainEventListener", mock.Anything, paladinListenerName).Return(true, nil)
	err = p.DeleteContractListener(ctx, &core.ContractListener{
		ID: listenerID,
	}, false)
	require.NoError(t, err)
	<-ctx.Done()
	assert.NotContains(t, p.eventLoops, listenerID.String())
}

func TestGetContractListenerStatus(t *testing.T) {
	p, mocks, ctx, cancel := newTestPaladin(t)
	defer cancel()

	listenerID := fftypes.NewUUID()
	paladinListenerName := fmt.Sprintf("ff-listener-%s", listenerID.String())

	// allow not found
	mocks.ptx.On("GetBlockchainEventListenerStatus", mock.Anything, paladinListenerName).Return(nil, errors.New("PD012248 Not Found")).Twice()
	found, _, _, err := p.GetContractListenerStatus(ctx, "ns1", paladinListenerName, true)
	assert.NoError(t, err)
	assert.False(t, found)

	// return error
	found, _, _, err = p.GetContractListenerStatus(ctx, "ns1", paladinListenerName, false)
	assert.ErrorContains(t, err, "PD012248")

	// error subscribing to listener
	mocks.ptx.On("GetBlockchainEventListenerStatus", mock.Anything, paladinListenerName).Return(&pldapi.BlockchainEventListenerStatus{
		Catchup: true,
		Checkpoint: pldapi.BlockchainEventListenerCheckpoint{
			BlockNumber: int64(100),
		},
	}, nil).Twice()
	mocks.ptx.On("SubscribeBlockchainEvents", mock.Anything, mock.Anything).Return(nil, errors.New("paladin error")).Once()
	found, _, _, err = p.GetContractListenerStatus(ctx, "ns1", paladinListenerName, false)
	assert.ErrorContains(t, err, "paladin error")

	// start loop and return status
	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(make(chan rpcclient.RPCSubscriptionNotification, 1)).Maybe()
	mocks.ptx.On("SubscribeBlockchainEvents", mock.Anything, paladinListenerName).Return(sub, nil)
	found, detail, status, err := p.GetContractListenerStatus(ctx, "ns1", paladinListenerName, false)
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, core.ContractListenerStatusSyncing, status)
	if assert.NotNil(t, detail) {
		listenerStatus := detail.(*pldapi.BlockchainEventListenerStatus)
		assert.True(t, listenerStatus.Catchup)
		assert.Equal(t, int64(100), listenerStatus.Checkpoint.BlockNumber)
	}

}

func TestContractListenerEventLoop(t *testing.T) {
	p, mocks, ctx, cancel := newTestPaladin(t)
	defer cancel()

	event := &pldapi.EventWithData{
		Address: *pldtypes.RandAddress(),
		Data:    pldtypes.RawJSON(`{"foo": "bar"}`),
		IndexedEvent: &pldapi.IndexedEvent{
			BlockNumber:      int64(1),
			TransactionIndex: int64(2),
			LogIndex:         int64(3),
			Block: &pldapi.IndexedBlock{
				Timestamp: pldtypes.TimestampNow(),
			},
		},
		SoliditySignature: "event event1(bytes32)",
	}
	batch := &pldapi.TransactionEventBatch{
		BatchID: uuid.New(),
		Events:  []*pldapi.EventWithData{event},
	}
	batchBytes, err := json.Marshal(batch)
	require.NoError(t, err)

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)
	notification.On("GetResult").Return(pldtypes.RawJSON(batchBytes))

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	go p.contractListenerEventLoop("ns1", "id", sub)

	prepare := mocks.callbacks.On("PrepareBlockchainEvent", mock.Anything, mock.Anything, "ns1", mock.Anything).Return()
	prepare.Run(func(args mock.Arguments) {
		eventForListener := args.Get(3).(*blockchain.EventForListener)
		assert.Equal(t, event.TransactionHash.HexString(), eventForListener.BlockchainTXID)
		assert.Equal(t, "paladin", eventForListener.Source)
		assert.Equal(t, "event1", eventForListener.Name)
		assert.NotNil(t, eventForListener.Output)
		assert.NotNil(t, eventForListener.Info)
		assert.Equal(t, "000000000001/000002/000003", eventForListener.ProtocolID)
		assert.Equal(t, "address="+event.Address.HexString(), eventForListener.Location)
		assert.Equal(t, event.SoliditySignature, eventForListener.Signature)
		assert.NotNil(t, eventForListener.Timestamp)
	})

	// dispatch error- nack and continue loop
	mocks.callbacks.On("DispatchBlockchainEvents", mock.Anything, mock.Anything).Return(errors.New("dispatch error")).Once()
	nack := notification.On("Nack", mock.Anything).Return(nil).Once()
	nacked := make(chan bool, 1)
	nack.Run(func(args mock.Arguments) {
		nacked <- true
	})
	c <- notification
	<-nacked

	// dispatch succeeds- ack and continue loop
	mocks.callbacks.On("DispatchBlockchainEvents", mock.Anything, mock.Anything).Return(nil).Once()
	ack := notification.On("Ack", mock.Anything).Return(nil).Once()
	acked := make(chan bool, 1)
	ack.Run(func(args mock.Arguments) {
		acked <- true
	})
	c <- notification
	<-acked

	// dispatch error- nack fails so cancel is called
	mocks.callbacks.On("DispatchBlockchainEvents", mock.Anything, mock.Anything).Return(errors.New("dispatch error")).Once()
	nackError := paladinrpcclientmocks.NewErrorRPC(t)
	nackError.On("Error").Return("nack err")
	notification.On("Nack", mock.Anything).Return(nackError).Once()
	c <- notification
	<-ctx.Done()
}

func TestSubmitBatchPin(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)

	// error parsing location
	location := fftypes.JSONAnyPtr(`{"address":"foo"`)
	err := p.SubmitBatchPin(ctx, "", "", "", nil, location)
	require.ErrorContains(t, err, "FF10310")

	// check the inputs to the send transaction rpc call
	addr := pldtypes.RandAddress().String()
	location = fftypes.JSONAnyPtr(fmt.Sprintf(`{"address":"%s"}`, addr))
	batch := &blockchain.BatchPin{
		Contexts:        []*fftypes.Bytes32{fftypes.NewRandB32()},
		TransactionID:   fftypes.NewUUID(),
		BatchID:         fftypes.NewUUID(),
		BatchHash:       fftypes.NewRandB32(),
		BatchPayloadRef: "ref",
	}
	sendTX := mocks.ptx.On("SendTransaction", mock.Anything, mock.Anything).Return(nil, nil).Once()
	sendTX.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionInput)
		assert.Equal(t, "nsOpID", tx.IdempotencyKey)
		assert.Equal(t, "signingKey", tx.From)
		assert.Equal(t, addr, tx.To.String())
	})
	err = p.SubmitBatchPin(ctx, "nsOpID", "ns", "signingKey", batch, location)
	require.NoError(t, err)
}

func TestSubmitNetworkAction(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)

	// error parsing location
	location := fftypes.JSONAnyPtr(`{"address":"foo"`)
	err := p.SubmitNetworkAction(ctx, "", "", core.NetworkActionTerminate, location)
	require.ErrorContains(t, err, "FF10310")

	// check the inputs to the send transaction rpc call
	addr := pldtypes.RandAddress().String()
	location = fftypes.JSONAnyPtr(fmt.Sprintf(`{"address":"%s"}`, addr))
	sendTX := mocks.ptx.On("SendTransaction", mock.Anything, mock.Anything).Return(nil, nil).Once()
	sendTX.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionInput)
		assert.Equal(t, "nsOpID", tx.IdempotencyKey)
		assert.Equal(t, "signingKey", tx.From)
		assert.Equal(t, addr, tx.To.String())
		assert.Equal(t, `["firefly:terminate",""]`, tx.Data.String())
	})
	err = p.SubmitNetworkAction(ctx, "nsOpID", "signingKey", core.NetworkActionTerminate, location)
	require.NoError(t, err)
}

func TestAddFireflySubscription(t *testing.T) {
	p, mocks, ctx, cancel := newTestPaladin(t)
	defer cancel()

	addr := pldtypes.RandAddress().String()
	namespace := &core.Namespace{
		Name: "ns1",
	}
	contract := &blockchain.MultipartyContract{
		Location: fftypes.JSONAnyPtr(`{"address":"foo"`),
	}
	name := "ns1_BatchPin_" + hex.EncodeToString(sha256.New().Sum([]byte(addr)))[0:16]

	// error parsing location
	_, err := p.AddFireflySubscription(ctx, namespace, contract, "")
	require.ErrorContains(t, err, "FF10310")

	// error getting network version
	contract.Location = fftypes.JSONAnyPtr(fmt.Sprintf(`{"address":"%s"}`, addr))
	mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(nil, errors.New("paladin error")).Once()
	_, err = p.AddFireflySubscription(ctx, namespace, contract, "")
	require.ErrorContains(t, err, "paladin error")

	// error resolving from block
	contract.FirstEvent = "banana"
	mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(pldtypes.RawJSON(`{"0":"2"}`), nil)
	_, err = p.AddFireflySubscription(ctx, namespace, contract, "")
	require.ErrorContains(t, err, "FF10473")

	// error creating blockchain event listener
	contract.FirstEvent = "latest"
	mocks.ptx.On("CreateBlockchainEventListener", mock.Anything, mock.Anything).Return(false, errors.New("paladin error")).Once()
	_, err = p.AddFireflySubscription(ctx, namespace, contract, "")
	require.ErrorContains(t, err, "paladin error")

	// error creating  subscription
	mocks.subs.On("AddSubscription", mock.Anything, namespace, 2, name, nil).Return()
	mocks.ptx.On("CreateBlockchainEventListener", mock.Anything, mock.Anything).Return(true, nil)
	mocks.ptx.On("SubscribeBlockchainEvents", mock.Anything, name).Return(nil, errors.New("paladin error")).Once()
	_, err = p.AddFireflySubscription(ctx, namespace, contract, "")
	require.ErrorContains(t, err, "paladin error")

	// success
	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(make(chan rpcclient.RPCSubscriptionNotification, 1)).Maybe()
	mocks.ptx.On("SubscribeBlockchainEvents", mock.Anything, name).Return(sub, nil)
	_, err = p.AddFireflySubscription(ctx, namespace, contract, "")
	require.NoError(t, err)
}

func TestFireflySubscriptionEventLoop(t *testing.T) {
	p, mocks, ctx, cancel := newTestPaladin(t)
	defer cancel()

	namespace := "ns1"
	id := "id"
	transactionID := fftypes.NewUUID()
	batchID := fftypes.NewUUID()
	var uuids fftypes.Bytes32
	copy(uuids[0:16], (*transactionID)[:])
	copy(uuids[16:32], (*batchID)[:])
	uuidsString := ethHexFormatB32(&uuids)
	batchHash := ethHexFormatB32(nil)
	payloadRef := "payloadRef"
	ethHash := ethHexFormatB32(fftypes.NewRandB32())

	addr := pldtypes.RandAddress()
	author := pldtypes.RandAddress().String()
	event := &pldapi.EventWithData{
		Address: *addr,
		Data: pldtypes.RawJSON(fmt.Sprintf(`{
			"author": "%s", 
			"namespace": "%s",
			"uuids": "%s",
			"batchHash": "%s",
			"payloadRef": "%s",
			"contexts": ["%s"]
		}`, author, namespace, uuidsString, batchHash, payloadRef, ethHash)),
		IndexedEvent: &pldapi.IndexedEvent{
			BlockNumber:      int64(1),
			TransactionIndex: int64(2),
			LogIndex:         int64(3),
			Block: &pldapi.IndexedBlock{
				Timestamp: pldtypes.TimestampNow(),
			},
		},
		SoliditySignature: "event BatchPin(address,uint256,string,bytes32,bytes32,string,bytes32[])",
	}
	batch := &pldapi.TransactionEventBatch{
		BatchID: uuid.New(),
		Events:  []*pldapi.EventWithData{event},
	}

	batchBytes, err := json.Marshal(batch)
	require.NoError(t, err)

	notification := paladinrpcclientmocks.NewRPCSubscriptionNotification(t)

	c := make(chan rpcclient.RPCSubscriptionNotification, 1)
	sub := paladinrpcclientmocks.NewSubscription(t)
	sub.On("Notifications").Return(c)

	nack := notification.On("Nack", mock.Anything).Return(nil)
	nacked := make(chan bool, 1)
	nack.Run(func(args mock.Arguments) {
		nacked <- true
	})

	go p.fireflySubscriptionEventLoop(namespace, id, sub)

	// subinfo is nil
	mocks.subs.On("GetSubscription", id).Return(nil).Once()
	notification.On("GetResult").Return(pldtypes.RawJSON(batchBytes)).Once()
	c <- notification
	<-nacked

	// bad from address
	// modify the data to have a bad author address then serialize again
	event.Data = pldtypes.RawJSON(`{
			"author": "0x1234"
		}`)
	batchBytesBadAddress, err := json.Marshal(batch)
	require.NoError(t, err)

	mocks.subs.On("GetSubscription", "id").Return(&common.SubscriptionInfo{Version: 2})
	notification.On("GetResult").Return(pldtypes.RawJSON(batchBytesBadAddress)).Once()
	c <- notification
	<-nacked

	// dispatch failure
	prepareMock := mocks.callbacks.On("PrepareBatchPinOrNetworkAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
	prepareMock.Run(func(args mock.Arguments) {
		subInfo := args.Get(2).(*common.SubscriptionInfo)
		assert.Equal(t, 2, subInfo.Version)
		location := args.Get(3).(*fftypes.JSONAny)
		assert.Equal(t, fmt.Sprintf(`{"address":"%s"}`, addr.String()), location.String())
		blockchainEvent := args.Get(4).(*blockchain.Event)
		assert.Equal(t, event.SoliditySignature, blockchainEvent.Signature)
		verifier := args.Get(5).(*core.VerifierRef)
		assert.Equal(t, core.VerifierTypeEthAddress, verifier.Type)
		assert.Equal(t, author, verifier.Value)
		params := args.Get(6).(*common.BatchPinParams)
		assert.Equal(t, uuidsString, params.UUIDs)
		assert.Equal(t, batchHash, params.BatchHash)
		assert.Equal(t, payloadRef, params.PayloadRef)
		assert.Equal(t, ethHash, params.Contexts[0])
		assert.Equal(t, namespace, params.NsOrAction)
	})
	mocks.callbacks.On("DispatchBlockchainEvents", mock.Anything, mock.Anything).Return(errors.New("dispatch error")).Once()
	notification.On("GetResult").Return(pldtypes.RawJSON(batchBytes)).Once()
	c <- notification
	<-nacked

	// success
	mocks.callbacks.On("DispatchBlockchainEvents", mock.Anything, mock.Anything).Return(nil)
	notification.On("GetResult").Return(pldtypes.RawJSON(batchBytes)).Once()
	ack := notification.On("Ack", mock.Anything).Return(nil).Once()
	acked := make(chan bool, 1)
	ack.Run(func(args mock.Arguments) {
		acked <- true
	})
	c <- notification
	<-acked

	// ack failure to force cancel
	notification.On("GetResult").Return(pldtypes.RawJSON(batchBytes)).Once()
	rpcError := paladinrpcclientmocks.NewErrorRPC(t)
	rpcError.On("Error").Return("ack error")
	ack = notification.On("Ack", mock.Anything).Return(rpcError).Once()
	c <- notification
	<-ctx.Done()
}

func TestRemoveFireflySubscription(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)
	id := "subID"

	// subscription not found
	mocks.subs.On("GetSubscription", id).Return(nil).Once()
	p.RemoveFireflySubscription(ctx, id)

	// error deleting blockchain event listener
	mocks.subs.On("GetSubscription", id).Return(&common.SubscriptionInfo{}).Twice()
	mocks.subs.On("RemoveSubscription", mock.Anything, id).Return().Twice()
	mocks.ptx.On("DeleteBlockchainEventListener", mock.Anything, id).Return(false, errors.New("paladin error")).Once()
	p.RemoveFireflySubscription(ctx, id)

	// success
	cancelled := false
	p.eventLoops[id] = func() {
		cancelled = true
	}
	mocks.ptx.On("DeleteBlockchainEventListener", mock.Anything, id).Return(true, nil).Once()
	p.RemoveFireflySubscription(ctx, id)
	assert.True(t, cancelled)
	assert.NotContains(t, p.eventLoops, id)
}

func TestGetNetworkVersion(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)
	addr := pldtypes.RandAddress().String()

	// invalid location
	_, err := p.GetNetworkVersion(ctx, fftypes.JSONAnyPtr("notanethaddress"))
	require.Error(t, err)

	// retrieve from contract
	call := mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(pldtypes.RawJSON(`{"0":"2"}`), nil).Once()
	call.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionCall)
		assert.Equal(t, addr, tx.To.String())
	})
	version, err := p.GetNetworkVersion(ctx, fftypes.JSONAnyPtr(fmt.Sprintf(`{"address":"%s"}`, addr)))
	require.NoError(t, err)
	assert.Equal(t, 2, version)

	// retrieve from cache
	version, err = p.GetNetworkVersion(ctx, fftypes.JSONAnyPtr(fmt.Sprintf(`{"address":"%s"}`, addr)))
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func TestQueryNetworkVersion(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)
	addr := pldtypes.RandAddress().String()

	// invalid address
	_, err := p.queryNetworkVersion(ctx, "notanethaddress")
	require.Error(t, err)

	// error querying contract
	mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(nil, errors.New("paladin error")).Once()
	_, err = p.queryNetworkVersion(ctx, addr)
	require.ErrorContains(t, err, "paladin error")

	// error unmarshalling response
	mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(pldtypes.RawJSON("{"), nil).Once()
	_, err = p.queryNetworkVersion(ctx, addr)
	require.Error(t, err)

	// response not a string
	mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(pldtypes.RawJSON(`{"0": 2}`), nil).Once()
	_, err = p.queryNetworkVersion(ctx, addr)
	require.ErrorContains(t, err, "FF10412")

	// success
	call := mocks.ptx.On("Call", mock.Anything, mock.Anything).Return(pldtypes.RawJSON(`{"0":"2"}`), nil).Once()
	call.Run(func(args mock.Arguments) {
		tx := args.Get(1).(*pldapi.TransactionCall)
		assert.Equal(t, addr, tx.To.String())
		assert.Equal(t, "", tx.From)
		assert.Equal(t, "networkVersion", tx.Function)
	})
	version, err := p.queryNetworkVersion(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func TestGetAndConvertDeprecatedContractConfig(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	_, _, err := p.GetAndConvertDeprecatedContractConfig(ctx)
	require.NoError(t, err)
}

func TestGetTransactionStatus(t *testing.T) {
	p, mocks, ctx, _ := newTestPaladin(t)

	id := fftypes.NewUUID()
	op := &core.Operation{
		ID:        id,
		Namespace: "ns1",
	}

	// paladin error
	mocks.ptx.On("QueryTransactionsFull", mock.Anything, mock.Anything).Return(nil, errors.New("paladin error")).Once()
	_, err := p.GetTransactionStatus(ctx, op)
	assert.Regexp(t, "FF10483.*paladin error", err)

	// no match
	mocks.ptx.On("QueryTransactionsFull", mock.Anything, mock.Anything).Return([]*pldapi.TransactionFull{}, nil).Once()
	tx, err := p.GetTransactionStatus(ctx, op)
	assert.NoError(t, err)
	assert.Nil(t, tx)

	// match
	qt := mocks.ptx.On("QueryTransactionsFull", mock.Anything, mock.Anything).Return([]*pldapi.TransactionFull{{
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
				Value: pldtypes.JSONString(fmt.Sprintf("ns1:%s", id)),
			}, filter.Statements.Ops.Eq[0])
		}
	})
	tx, err = p.GetTransactionStatus(ctx, op)
	require.NoError(t, err)
	require.NotNil(t, tx)
}

func TestParseInterface(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

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

func TestToJSONObject(t *testing.T) {
	obj := toJSONObject(nil)
	require.Nil(t, obj)

	input := struct{ A string }{A: "foo"}
	obj = toJSONObject(input)
	require.NotNil(t, obj)
	assert.Equal(t, "foo", obj.GetString("A"))
}

// tests for duplicated functions below this point

func TestResolveFromBlockCombinations(t *testing.T) {
	ctx := context.Background()

	fromBlock, err := resolveFromBlock(ctx, "", "")
	assert.Equal(t, "latest", fromBlock)
	assert.NoError(t, err)

	fromBlock, err = resolveFromBlock(ctx, "latest", "")
	assert.Equal(t, "latest", fromBlock)
	assert.NoError(t, err)

	fromBlock, err = resolveFromBlock(ctx, "newest", "")
	assert.Equal(t, "latest", fromBlock)
	assert.NoError(t, err)

	fromBlock, err = resolveFromBlock(ctx, "oldest", "")
	assert.Equal(t, "0", fromBlock)
	assert.NoError(t, err)

	fromBlock, err = resolveFromBlock(ctx, "0", "")
	assert.Equal(t, "0", fromBlock)
	assert.NoError(t, err)

	fromBlock, err = resolveFromBlock(ctx, "0", "000000000010/000000/000050")
	assert.Equal(t, "9", fromBlock)
	assert.NoError(t, err)

	fromBlock, err = resolveFromBlock(ctx, "20", "000000000010/000000/000050")
	assert.Equal(t, "20", fromBlock)
	assert.NoError(t, err)

	fromBlock, err = resolveFromBlock(ctx, "", "000000000010/000000/000050")
	assert.Equal(t, "9", fromBlock)
	assert.NoError(t, err)

	_, err = resolveFromBlock(ctx, "", "wrong")
	assert.Regexp(t, "FF10472", err)

}

func TestGenerateFFI(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

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
	p, _, ctx, _ := newTestPaladin(t)

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

func TestGetFFIParamValidator(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	validator, err := p.GetFFIParamValidator(ctx)
	require.NoError(t, err)
	assert.Implements(t, (*fftypes.FFIParamValidator)(nil), validator)
}

func TestGenerateEventSignature(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)
	complexParam := fftypes.JSONObject{
		"type": "object",
		"details": fftypes.JSONObject{
			"type": "tuple",
		},
		"properties": fftypes.JSONObject{
			"prop1": fftypes.JSONObject{
				"type": "integer",
				"details": fftypes.JSONObject{
					"type":  "uint256",
					"index": 0,
				},
			},
			"prop2": fftypes.JSONObject{
				"type": "integer",
				"details": fftypes.JSONObject{
					"type":  "uint256",
					"index": 1,
				},
			},
		},
	}.String()

	event := &fftypes.FFIEventDefinition{
		Name: "Changed",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "y",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "z",
				Schema: fftypes.JSONAnyPtr(complexParam),
			},
		},
	}

	signature, err := p.GenerateEventSignature(ctx, event)
	assert.NoError(t, err)
	assert.Equal(t, "Changed(uint256,uint256,(uint256,uint256))", signature)
}

func TestGenerateEventSignatureWithIndexedFields(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)
	complexParam := fftypes.JSONObject{
		"type": "object",
		"details": fftypes.JSONObject{
			"type": "tuple",
		},
		"properties": fftypes.JSONObject{
			"prop1": fftypes.JSONObject{
				"type": "integer",
				"details": fftypes.JSONObject{
					"type":  "uint256",
					"index": 0,
				},
			},
			"prop2": fftypes.JSONObject{
				"type": "integer",
				"details": fftypes.JSONObject{
					"type":    "uint256",
					"index":   1,
					"indexed": true,
				},
			},
		},
	}.String()

	event := &fftypes.FFIEventDefinition{
		Name: "Changed",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "y",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256", "indexed": true}}`),
			},
			{
				Name:   "z",
				Schema: fftypes.JSONAnyPtr(complexParam),
			},
		},
	}

	signature, err := p.GenerateEventSignature(ctx, event)
	assert.NoError(t, err)
	assert.Equal(t, "Changed(uint256,uint256,(uint256,uint256)) [i=1]", signature)
}

func TestGenerateEventSignatureWithEmptyDefinition(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	event := &fftypes.FFIEventDefinition{
		Name: "Empty",
	}

	signature, err := p.GenerateEventSignature(ctx, event)
	assert.NoError(t, err)
	assert.Equal(t, "Empty()", signature)
}

func TestGenerateEventSignatureInvalid(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	event := &fftypes.FFIEventDefinition{
		Name: "Changed",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"!bad": "bad"`),
			},
		},
	}

	signature, err := p.GenerateEventSignature(ctx, event)
	assert.Error(t, err)
	assert.Equal(t, "", signature)
}

func TestGenerateErrorSignature(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	complexParam := fftypes.JSONObject{
		"type": "object",
		"details": fftypes.JSONObject{
			"type": "tuple",
		},
		"properties": fftypes.JSONObject{
			"prop1": fftypes.JSONObject{
				"type": "integer",
				"details": fftypes.JSONObject{
					"type":  "uint256",
					"index": 0,
				},
			},
			"prop2": fftypes.JSONObject{
				"type": "integer",
				"details": fftypes.JSONObject{
					"type":  "uint256",
					"index": 1,
				},
			},
		},
	}.String()

	errorDef := &fftypes.FFIErrorDefinition{
		Name: "CustomError",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "y",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "z",
				Schema: fftypes.JSONAnyPtr(complexParam),
			},
		},
	}

	signature := p.GenerateErrorSignature(ctx, errorDef)
	assert.Equal(t, "CustomError(uint256,uint256,(uint256,uint256))", signature)
}

func TestGenerateErrorSignatureInvalid(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	event := &fftypes.FFIErrorDefinition{
		Name: "CustomError",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"!bad": "bad"`),
			},
		},
	}

	signature := p.GenerateErrorSignature(ctx, event)
	assert.Equal(t, "", signature)
}

func TestGenerateEventSignatureWithLocation(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)
	location := &Location{
		Address: "3081D84FD367044F4ED453F2024709242470388C",
	}

	event := &fftypes.FFIEventDefinition{
		Name: "Changed",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "y",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
		},
	}
	locationBytes, err := json.Marshal(location)
	assert.NoError(t, err)
	result, err := p.GenerateEventSignatureWithLocation(ctx, event, fftypes.JSONAnyPtrBytes(locationBytes))
	assert.NoError(t, err)
	assert.Equal(t, "3081D84FD367044F4ED453F2024709242470388C:Changed(uint256,uint256)", result)
}

func TestGenerateEventSignatureWithEmptyLocation(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	event := &fftypes.FFIEventDefinition{
		Name: "Changed",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "y",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
		},
	}
	result, err := p.GenerateEventSignatureWithLocation(ctx, event, nil)
	assert.NoError(t, err)
	assert.Equal(t, "*:Changed(uint256,uint256)", result)
}

func TestGenerateEventSignatureWithLocationInvalidABI(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	event := &fftypes.FFIEventDefinition{
		Name: "Changed",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"invalid abi"}}`),
			},
		},
	}
	_, err := p.GenerateEventSignatureWithLocation(ctx, event, nil)
	assert.Error(t, err)
	assert.Regexp(t, "FF22052", err.Error())
}

func TestGenerateEventSignatureWithLocationInvalidLocation(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)

	event := &fftypes.FFIEventDefinition{
		Name: "Changed",
		Params: []*fftypes.FFIParam{
			{
				Name:   "x",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
			{
				Name:   "y",
				Schema: fftypes.JSONAnyPtr(`{"type": "integer", "details": {"type": "uint256"}}`),
			},
		},
	}
	locationBytes, err := json.Marshal("{}")
	assert.NoError(t, err)
	_, err = p.GenerateEventSignatureWithLocation(ctx, event, fftypes.JSONAnyPtrBytes(locationBytes))
	assert.Error(t, err)
	assert.Regexp(t, "FF10310", err.Error())
}

func TestCheckOverLappingLocationsEmpty(t *testing.T) {
	p, _, ctx, _ := newTestPaladin(t)
	result, err := p.CheckOverlappingLocations(ctx, nil, nil)
	assert.NoError(t, err)
	assert.True(t, result)
}

func TestCheckOverLappingLocationsBadLocation(t *testing.T) {
	locationBytes, err := json.Marshal("{}")
	assert.NoError(t, err)
	p, _, ctx, _ := newTestPaladin(t)
	_, err = p.CheckOverlappingLocations(ctx, fftypes.JSONAnyPtrBytes(locationBytes), fftypes.JSONAnyPtrBytes(locationBytes))
	assert.Error(t, err)
	assert.Regexp(t, "FF10310", err.Error())
}

func TestCheckOverLappingLocationsBadLocationSecond(t *testing.T) {
	location := &Location{
		Address: "3081D84FD367044F4ED453F2024709242470388C",
	}
	goodLocationBytes, err := json.Marshal(location)
	assert.NoError(t, err)

	badLocationBytes, err := json.Marshal("{}")
	assert.NoError(t, err)
	p, _, ctx, _ := newTestPaladin(t)
	_, err = p.CheckOverlappingLocations(ctx, fftypes.JSONAnyPtrBytes(goodLocationBytes), fftypes.JSONAnyPtrBytes(badLocationBytes))
	assert.Error(t, err)
	assert.Regexp(t, "FF10310", err.Error())
}

func TestCheckOverLappingLocationsSame(t *testing.T) {
	location := &Location{
		Address: "3081D84FD367044F4ED453F2024709242470388C",
	}
	locationBytes, err := json.Marshal(location)
	assert.NoError(t, err)

	p, _, ctx, _ := newTestPaladin(t)
	result, err := p.CheckOverlappingLocations(ctx, fftypes.JSONAnyPtrBytes(locationBytes), fftypes.JSONAnyPtrBytes(locationBytes))
	assert.NoError(t, err)
	assert.True(t, result)
}
