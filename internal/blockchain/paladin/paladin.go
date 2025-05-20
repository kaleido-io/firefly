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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ffi2abi"
	"github.com/hyperledger/firefly/internal/blockchain/common"
	"github.com/hyperledger/firefly/internal/cache"
	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/internal/metrics"
	"github.com/hyperledger/firefly/pkg/blockchain"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/sdk/go/pkg/pldapi"
	"github.com/kaleido-io/paladin/sdk/go/pkg/pldclient"
	"github.com/kaleido-io/paladin/sdk/go/pkg/pldtypes"
	"github.com/kaleido-io/paladin/sdk/go/pkg/query"
	"github.com/kaleido-io/paladin/sdk/go/pkg/rpcclient"
	"github.com/sirupsen/logrus"
)

type Paladin struct {
	ctx              context.Context
	cancelCtx        context.CancelFunc // this is the cancel context for the whole FireFly server
	metrics          metrics.Manager
	capabilities     *blockchain.Capabilities
	callbacks        common.BlockchainCallbacks
	httpClientConfig pldconf.HTTPClientConfig
	httpClient       pldclient.PaladinClient
	// this looks like we have two things of the same type but it needs to be
	// this way because the http client doesn't work for creating a working WSClient
	pldClient            pldclient.PaladinClient
	wsClientConfig       pldconf.WSClientConfig
	wsconn               map[string]pldclient.PaladinWSClient
	eventLoops           map[string]context.CancelFunc
	subs                 common.FireflySubscriptions
	cache                cache.CInterface
	addressResolveAlways bool
	addressResolver      *addressResolver
}

func (p *Paladin) Name() string {
	return "paladin"
}

func (p *Paladin) VerifierType() core.VerifierType {
	return core.VerifierTypeEthAddress
}

func (p *Paladin) Init(ctx context.Context, cancelCtx context.CancelFunc, config config.Section, metrics metrics.Manager, cacheManager cache.Manager) error {
	p.InitConfig(config)

	p.ctx = log.WithLogField(ctx, "proto", "paladin")
	p.cancelCtx = cancelCtx
	p.metrics = metrics
	p.capabilities = &blockchain.Capabilities{}
	p.callbacks = common.NewBlockchainCallbacks()
	p.subs = common.NewFireflySubscriptions()
	p.eventLoops = make(map[string]context.CancelFunc)

	// This is not great
	// - Convert from ffresty to Paladin HTTP Config
	// - Then Paladin just converts back to FF Resty
	clientConfig := config.SubSection(PaladinRPCClientConfigKey)

	httpRestyConfig, err := ffresty.GenerateConfig(ctx, clientConfig)
	var wsRestyConfig *wsclient.WSConfig
	if err == nil {
		wsRestyConfig, err = wsclient.GenerateConfig(ctx, clientConfig)
	}
	if err != nil {
		return err
	}

	p.httpClientConfig = pldconf.HTTPClientConfig{
		URL:         httpRestyConfig.URL,
		HTTPHeaders: httpRestyConfig.HTTPHeaders,
		Auth: pldconf.HTTPBasicAuthConfig{
			Username: httpRestyConfig.AuthUsername,
			Password: httpRestyConfig.AuthPassword,
		},
	}

	p.wsClientConfig = pldconf.WSClientConfig{
		HTTPClientConfig: pldconf.HTTPClientConfig{
			URL:         wsRestyConfig.WebSocketURL,
			HTTPHeaders: wsRestyConfig.HTTPHeaders,
			Auth: pldconf.HTTPBasicAuthConfig{
				Username: wsRestyConfig.AuthUsername,
				Password: wsRestyConfig.AuthPassword,
			},
		},
	}

	p.httpClient, err = pldclient.New().HTTP(ctx, &p.httpClientConfig)
	if err != nil {
		return err
	}
	p.pldClient = pldclient.New()

	p.wsconn = make(map[string]pldclient.PaladinWSClient)

	cache, err := cacheManager.GetCache(
		cache.NewCacheConfig(
			ctx,
			coreconfig.CacheBlockchainLimit,
			coreconfig.CacheBlockchainTTL,
			"",
		),
	)
	if err != nil {
		return err
	}
	p.cache = cache

	addressResolverConf := config.SubSection(AddressResolverConfigKey)
	if addressResolverConf.GetBool(AddressResolverEnabled) {
		p.addressResolveAlways = addressResolverConf.GetBool(AddressResolverAlwaysResolve)
		p.addressResolver, err = newAddressResolver(ctx, addressResolverConf, cacheManager, !p.addressResolveAlways)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Paladin) StartNamespace(ctx context.Context, name string) error {
	// Websocket Client per Namespace
	log.L(p.ctx).Debugf("Starting namespace: %s", name)

	// try to start the receipt listener
	_, err := p.httpClient.PTX().StartReceiptListener(ctx, name)
	if err != nil {
		if strings.Contains(err.Error(), "PD012238") {
			_, err = p.httpClient.PTX().CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
				Name: name,
			})
		}
		if err != nil {
			return err
		}
	}

	p.wsconn[name], err = p.pldClient.WebSocket(ctx, &p.wsClientConfig)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		// cancel on the namespace context should always be called before the namespace is stopped and the
		// reference to the connection deleted so this check shouldn't be necessary but preferring to be
		// defensive than risk a nil pointer exception
		if p.wsconn[name] != nil {
			p.wsconn[name].Close()
		}
	}()

	sub, err := p.wsconn[name].PTX().SubscribeReceipts(ctx, name)
	if err != nil {
		return err
	}

	go p.receiptEventLoop(name, sub)

	return nil
}

func (p *Paladin) receiptEventLoop(namespace string, sub rpcclient.Subscription) {
	l := log.L(p.ctx).WithField("role", "event-loop").WithField("namespace", namespace)
	l.Debugf("Starting event loop for namespace '%s'", namespace)

	ctx := log.WithLogger(p.ctx, l)

	cancel := func() {
		l.Error("Event loop exiting. Terminating server!")
		// This cancels the context of the whole FireFly server!
		p.cancelCtx()
	}

	// Run an event loop to fetch receipts and update an operation
	go batchEventLoop(ctx, l, cancel, sub, func(batch *pldapi.TransactionReceiptBatch) error {
		updates := []*core.OperationUpdate{}
		// if there is an error processing any of the receipts we nack the batch (although not clear
		// why we would expect a different result the next time around)
		for _, receipt := range batch.Receipts {
			// For now, we need to get the transaction to get the idempotency Key
			// Might be fixed through https://github.com/LF-Decentralized-Trust-labs/paladin/issues/551
			tx, err := p.httpClient.PTX().GetTransactionFull(ctx, receipt.TransactionReceipt.ID)
			if err != nil {
				l.Errorf("Receipt cannot be processed - failed to get transaction by ID: %+v", receipt)
				return err
			}

			var status core.OpStatus
			if receipt.TransactionReceipt.Success {
				status = core.OpStatusSucceeded
			} else {
				status = core.OpStatusFailed
			}

			// The IdempotencyKey contains the FireFly Operation ID
			nsOpID := tx.IdempotencyKey

			// We need to cross check and see if we actually care about this operation!
			// Not all transaction receipts in Paladin are for those that this FireFly has submitted!
			opNamespace, _, _ := core.ParseNamespacedOpID(ctx, nsOpID)
			if opNamespace != namespace {
				l.Debugf("Ignoring operation update for transaction request=%s tx=%s", nsOpID, receipt.TransactionHash)
				continue
			}

			// Paladin isn't a fftm connector so doesn't return natively in the
			// common.BlockchainReceiptNotification format
			// We can probably wrangle it into this format for the output but lets start by taking
			// the paladin receipt as it and seeing whether this is ok
			updates = append(updates, &core.OperationUpdate{
				Plugin:         p.Name(),
				NamespacedOpID: nsOpID,
				Status:         status,
				BlockchainTXID: receipt.TransactionHash.String(),
				ErrorMessage:   receipt.FailureMessage,
				Output:         toJSONObject(receipt),
			})
		}

		if len(updates) > 0 {
			// We have a batch of operation updates
			if err := p.callbacks.BulkOperationUpdates(ctx, namespace, updates); err != nil {
				l.Error("Failed to commit batch updates")
				return err
			}
		}
		return nil
	})
}

func batchEventLoop[B any](ctx context.Context, l *logrus.Entry, cancel func(), sub rpcclient.Subscription, handler func(*B) error) {
	for {
		select {
		case <-ctx.Done():
			l.Debugf("Event loop exiting (context cancelled)")
			return
		case subNotification, ok := <-sub.Notifications():
			if !ok {
				// When the ws connection is closed, we get the not ok result here
				l.Info("Unable to read from subscription- websocket closed")
				cancel()
				return
			}

			var batch B

			if err := json.Unmarshal(subNotification.GetResult(), &batch); err != nil {
				l.Error("Unable to unmarshall subscription")
				if err := nackAndLogError(ctx, subNotification, l, err); err != nil {
					cancel()
					return
				}
				continue
			}

			if err := handler(&batch); err != nil {
				if err := nackAndLogError(ctx, subNotification, l, err); err != nil {
					cancel()
					return
				}
				continue
			}

			l.Debug("All events from websocket handled")
			// We only send this ACK once the handler has committed all the DB writes
			if err := subNotification.Ack(ctx); err != nil {
				l.Errorf("Failed to ack batch (%s)", err)
				cancel()
				return
			}
		}
	}
}

func nackAndLogError(ctx context.Context, s rpcclient.RPCSubscriptionNotification, l *logrus.Entry, err error) error {
	l.Errorf("NACKing subscription (%s)", err)

	nackErr := s.Nack(ctx)
	if nackErr != nil {
		l.Errorf("Failed to NACK subscription (%s)", nackErr)
		l.Error("Event loop exiting . Terminating server!")
	}
	return nackErr
}

func (p *Paladin) StopNamespace(ctx context.Context, name string) error {
	_, err := p.httpClient.PTX().StopReceiptListener(ctx, name)
	if err != nil {
		// just log the error - it doesn't stop anything from working if we don't manage to stop the listener
		// the benefit of calling stop is that it saves unnecessary CPU cycles in the Paladin node while
		// we're not listening
		log.L(p.ctx).Warnf("Failed to stop paladin receipt listener for namespace: %s", name)
	}

	// the context should have already been cancelled resulting in the ws connection being closed already
	// but to be extra sure we've tidied up properly we attempt to close it again here
	wsconn, ok := p.wsconn[name]
	if ok {
		wsconn.Close()
	}
	delete(p.wsconn, name)

	return nil
}

func (p *Paladin) SetHandler(namespace string, handler blockchain.Callbacks) {
	p.callbacks.SetHandler(namespace, handler)
}

func (p *Paladin) SetOperationHandler(namespace string, handler core.OperationCallbacks) {
	p.callbacks.SetOperationalHandler(namespace, handler)
}

func (p *Paladin) Capabilities() *blockchain.Capabilities {
	return p.capabilities
}

func (p *Paladin) ResolveSigningKey(ctx context.Context, keyRef string, intent blockchain.ResolveKeyIntent) (resolved string, err error) {
	// Key may be unset for query intent only
	if keyRef == "" {
		if intent == blockchain.ResolveKeyIntentQuery {
			return "", nil
		}
		return "", i18n.NewError(ctx, coremsgs.MsgNodeMissingBlockchainKey)
	}

	if p.addressResolver != nil {
		if !p.addressResolveAlways {
			// If there's no address resolver plugin, or addressResolveAlways is false,
			// we check if it's already an ethereum address - in which case we can just return it.
			resolved, err = formatEthAddress(ctx, keyRef)
		}
		if p.addressResolveAlways || err != nil {
			// Either it's not a valid ethereum address,
			// or we've been configured to invoke the address resolver on every call
			resolved, err = p.addressResolver.ResolveSigningKey(ctx, keyRef, intent)
			if err == nil {
				log.L(ctx).Infof("Key '%s' resolved to '%s'", keyRef, resolved)
				return resolved, nil
			}
		}
		return resolved, err

	}
	// There's no address resolver configured so go straight to Paladin if not already an eth address
	if resolved, err := formatEthAddress(ctx, keyRef); err == nil {
		return resolved, nil
	}
	return p.httpClient.PTX().ResolveVerifier(ctx, keyRef, "ecdsa:secp256k1", "eth_address")
}

func (p *Paladin) DeployContract(ctx context.Context, nsOpID, signingKey string, definition, contract *fftypes.JSONAny, input []interface{}, options map[string]interface{}) (submissionRejected bool, err error) {
	if p.metrics.IsMetricsEnabled() {
		p.metrics.BlockchainContractDeployment()
	}

	bytecode, err := pldtypes.ParseHexBytes(ctx, contract.AsString())
	if err != nil {
		return true, err
	}

	// Parse the ABI
	var a abi.ABI
	err = json.Unmarshal(definition.Bytes(), &a)
	if err != nil {
		// There shouldn't be an error here because the definition should already have been validated
		return true, err
	}

	tx := &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{
			IdempotencyKey: nsOpID,
			Type:           pldapi.TransactionTypePublic.Enum(),
			From:           signingKey,
			Data:           pldtypes.JSONString(input),
		},
		ABI:      a,
		Bytecode: bytecode,
	}

	err = p.setOptions(ctx, options, tx)
	if err != nil {
		return true, err
	}

	_, err = p.httpClient.PTX().SendTransaction(ctx, tx)

	return false, err
}

func (p *Paladin) ValidateInvokeRequest(ctx context.Context, parsedMethod interface{}, input map[string]interface{}, hasMessage bool) error {
	_, _, err := p.prepareRequest(ctx, parsedMethod, input)
	return err
}

func (p *Paladin) setOptions(ctx context.Context, options map[string]interface{}, tx *pldapi.TransactionInput) error {
	var err error
	if options["gasLimit"] != nil {
		gasLimit, err := pldtypes.ParseHexUint64(ctx, options["gasLimit"].(string))
		if err != nil {
			return err
		}
		tx.Gas = &gasLimit
	}

	if options["gasPrice"] != nil {
		tx.GasPrice, err = pldtypes.ParseHexUint256(ctx, options["gasPrice"].(string))
		if err != nil {
			return err
		}
	}

	if options["maxFeePerGas"] != nil {
		tx.MaxFeePerGas, err = pldtypes.ParseHexUint256(ctx, options["maxFeePerGas"].(string))
		if err != nil {
			return err
		}
	}

	if options["maxPriorityFeePerGas"] != nil {
		tx.MaxPriorityFeePerGas, err = pldtypes.ParseHexUint256(ctx, options["maxPriorityFeePerGas"].(string))
		if err != nil {
			return err
		}
	}

	if options["value"] != nil {
		tx.Value, err = pldtypes.ParseHexUint256(ctx, options["value"].(string))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Paladin) InvokeContract(ctx context.Context, nsOpID, signingKey string, location *fftypes.JSONAny, parsedMethod interface{}, input map[string]interface{}, options map[string]interface{}, batch *blockchain.BatchPin) (submissionRejected bool, err error) {
	to, err := p.parseContractLocationPLDAddress(ctx, location)
	if err != nil {
		return true, err
	}

	methodInfo, orderedInput, err := p.prepareRequest(ctx, parsedMethod, input)
	if err != nil {
		return true, err
	}

	if batch != nil {
		err := p.checkDataSupport(ctx, methodInfo.methodABI)
		if err == nil {
			method, batchPin := p.buildBatchPinInput(batch)
			encoded, err := method.Inputs.EncodeABIDataValuesCtx(ctx, batchPin)
			if err == nil {
				orderedInput[len(orderedInput)-1] = hex.EncodeToString(encoded)
			}
		}
		if err != nil {
			return true, err
		}
	}

	return p.invokeContractMethod(ctx, to, signingKey, methodInfo.methodABI, orderedInput, options, nsOpID)
}

func (p *Paladin) invokeContractMethod(ctx context.Context, to *pldtypes.EthAddress, signingKey string, methodABI *abi.Entry, input []interface{}, options map[string]interface{}, idempotencyKey string) (submissionRejected bool, err error) {
	if p.metrics.IsMetricsEnabled() {
		p.metrics.BlockchainTransaction(to.String(), methodABI.Name)
	}

	tx := &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{
			Type:     pldapi.TransactionTypePublic.Enum(),
			From:     signingKey,
			To:       to,
			Data:     pldtypes.JSONString(input),
			Function: methodABI.Name,
		},
		ABI: []*abi.Entry{methodABI},
	}

	if idempotencyKey != "" {
		tx.IdempotencyKey = idempotencyKey
	}

	err = p.setOptions(ctx, options, tx)
	if err != nil {
		return true, err
	}

	_, err = p.httpClient.PTX().SendTransaction(ctx, tx)

	return false, err
}

func (p *Paladin) QueryContract(ctx context.Context, signingKey string, location *fftypes.JSONAny, parsedMethod interface{}, input map[string]interface{}, options map[string]interface{}) (interface{}, error) {
	to, err := p.parseContractLocationPLDAddress(ctx, location)
	if err != nil {
		return true, err
	}

	methodInfo, orderedInput, err := p.prepareRequest(ctx, parsedMethod, input)
	if err != nil {
		return nil, err
	}

	return p.queryContractMethod(ctx, to, signingKey, methodInfo.methodABI, orderedInput, options)
}

func (p *Paladin) queryContractMethod(ctx context.Context, to *pldtypes.EthAddress, signingKey string, methodABI *abi.Entry, input []interface{}, options map[string]interface{}) (pldtypes.RawJSON, error) {
	if p.metrics.IsMetricsEnabled() {
		p.metrics.BlockchainQuery(to.String(), methodABI.Name)
	}

	tx := &pldapi.TransactionCall{
		TransactionInput: pldapi.TransactionInput{
			TransactionBase: pldapi.TransactionBase{
				Type:     pldapi.TransactionTypePublic.Enum(),
				From:     signingKey,
				To:       to,
				Data:     pldtypes.JSONString(input),
				Function: methodABI.Name,
			},
			ABI: []*abi.Entry{methodABI},
		},
	}

	err := p.setOptions(ctx, options, &tx.TransactionInput)
	if err != nil {
		return nil, err
	}

	if blockNumber, ok := options["blockNumber"]; ok {
		switch result := blockNumber.(type) {
		case json.Number:
			tx.Block = pldtypes.HexUint64OrString(result.String())
		case string:
			tx.Block = pldtypes.HexUint64OrString(result)
		}
	}

	return p.httpClient.PTX().Call(ctx, tx)
}

func (p *Paladin) AddContractListener(ctx context.Context, listener *core.ContractListener, lastProtocolID string) error {
	bel := &pldapi.BlockchainEventListener{
		Name: p.getPaladinEventListenerName(listener.ID.String()),
	}

	for _, f := range listener.Filters {
		filterABI, err := ffi2abi.ConvertFFIEventDefinitionToABI(ctx, &f.Event.FFIEventDefinition)
		if err != nil {
			return i18n.WrapError(ctx, err, coremsgs.MsgContractParamInvalid)
		}
		source := pldapi.BlockchainEventListenerSource{
			ABI: abi.ABI{filterABI},
		}
		if f.Location != nil {
			source.Address, err = p.parseContractLocationPLDAddress(ctx, f.Location)
			if err != nil {
				return err
			}
		}
		bel.Sources = append(bel.Sources, source)
	}
	firstEvent := string(core.SubOptsFirstEventNewest)
	if listener.Options != nil {
		firstEvent = listener.Options.FirstEvent
	}

	fromBlock, err := resolveFromBlock(ctx, firstEvent, lastProtocolID)
	if err != nil {
		return i18n.WrapError(ctx, err, coremsgs.MsgInvalidFromBlockNumber, firstEvent)
	}
	bel.Options.FromBlock = json.RawMessage(fmt.Sprintf("\"%s\"", fromBlock))

	_, err = p.httpClient.PTX().CreateBlockchainEventListener(ctx, bel)
	if err != nil {
		return i18n.WrapError(ctx, err, coremsgs.MsgPaladinConnectorRESTErr)
	}
	listener.BackendID = bel.Name

	sub, err := p.wsconn[listener.Namespace].PTX().SubscribeBlockchainEvents(ctx, bel.Name)
	if err != nil {
		return i18n.WrapError(ctx, err, coremsgs.MsgPaladinConnectorRESTErr)
	}

	go p.contractListenerEventLoop(listener.Namespace, listener.ID.String(), sub)
	return nil
}

func (p *Paladin) DeleteContractListener(ctx context.Context, listener *core.ContractListener, okNotFound bool) error {
	if cancel, ok := p.eventLoops[listener.ID.String()]; ok {
		cancel()
		delete(p.eventLoops, listener.ID.String())
	}

	_, err := p.httpClient.PTX().DeleteBlockchainEventListener(ctx, p.getPaladinEventListenerName(listener.ID.String()))
	if err != nil && !p.allowNotFound(err, okNotFound) {
		return i18n.WrapError(ctx, err, coremsgs.MsgPaladinConnectorRESTErr)
	}
	return nil
}

func (p *Paladin) GetContractListenerStatus(ctx context.Context, namespace, backendID string, okNotFound bool) (found bool, detail interface{}, status core.ContractListenerStatus, err error) {
	listenerStatus, err := p.httpClient.PTX().GetBlockchainEventListenerStatus(ctx, backendID)
	if err != nil {
		if p.allowNotFound(err, okNotFound) {
			return false, nil, core.ContractListenerStatusUnknown, nil
		}
		return false, nil, core.ContractListenerStatusUnknown, i18n.WrapError(ctx, err, coremsgs.MsgPaladinConnectorRESTErr)
	}

	// start the event loop here if we don't already have one
	listenerID := p.getContractListenerIDFromPaladinEventListenerName(backendID)
	if _, ok := p.eventLoops[listenerID]; !ok {
		sub, err := p.wsconn[namespace].PTX().SubscribeBlockchainEvents(ctx, backendID)
		if err != nil {
			return true, nil, core.ContractListenerStatusUnknown, i18n.WrapError(ctx, err, coremsgs.MsgPaladinConnectorRESTErr)

		}
		go p.contractListenerEventLoop(namespace, listenerID, sub)
	}

	status = core.ContractListenerStatusSynced
	if listenerStatus.Catchup {
		status = core.ContractListenerStatusSyncing
	}
	return true, listenerStatus, status, nil
}

func (p *Paladin) contractListenerEventLoop(namespace string, id string, sub rpcclient.Subscription) {
	l := log.L(p.ctx).
		WithField("role", "contract-listener").
		WithField("namespace", namespace).
		WithField("id", id)

	eventLoopCtx, eventLoopCancelCtx := context.WithCancel(p.ctx)
	eventLoopCtx = log.WithLogger(eventLoopCtx, l)
	p.eventLoops[id] = eventLoopCancelCtx

	// cancel is called if the event loop hits irrecoverable errors
	cancel := func() {
		l.Error("Event loop exiting. Terminating server!")
		// This cancels the context of the whole FireFly server!
		p.cancelCtx()
	}

	l.Debugf("Starting event loop for contract listener '%s:%s'", namespace, id)
	batchEventLoop(eventLoopCtx, l, cancel, sub, func(batch *pldapi.TransactionEventBatch) error {
		eventsToDispatch := make(common.EventsToDispatch)
		for _, event := range batch.Events {
			eventForListener := &blockchain.EventForListener{
				ListenerID: p.getPaladinEventListenerName(id),
				Event:      p.parseBlockchainEvent(event),
			}
			p.callbacks.PrepareBlockchainEvent(eventLoopCtx, eventsToDispatch, namespace, eventForListener)
		}
		err := p.callbacks.DispatchBlockchainEvents(eventLoopCtx, eventsToDispatch)
		if err != nil {
			l.Error("Failed to dispatch event batch")
			return err
		}
		return nil
	})
}

func (p *Paladin) parseBlockchainEvent(event *pldapi.EventWithData) *blockchain.Event {
	eventName := strings.SplitN(event.SoliditySignature, "(", 2)[0][6:] // e.g. event DataStored(uint256 data) -> DataStored
	protocolID := fmt.Sprintf("%.12d/%.6d/%.6d", event.BlockNumber, event.TransactionIndex, event.LogIndex)
	locationString := fmt.Sprintf("address=%s", event.Address.HexString())
	info := toJSONObject(event)
	delete(info, "data")

	// The timestamp cannot be invalid if it has been stringified from the Paladin timestamp type
	timestamp, _ := fftypes.ParseTimeString(event.Block.Timestamp.String())

	return &blockchain.Event{
		BlockchainTXID: event.TransactionHash.HexString(),
		Source:         p.Name(),
		Name:           eventName,
		ProtocolID:     protocolID,
		Output:         event.Data.ToMap(),
		Info:           info,
		Location:       locationString,
		Signature:      event.SoliditySignature,
		Timestamp:      timestamp,
	}
}

func (p *Paladin) allowNotFound(err error, okNotFound bool) bool {
	return okNotFound && strings.Contains(err.Error(), "PD012248")
}

func (p *Paladin) getPaladinEventListenerName(id string) string {
	return fmt.Sprintf("ff-listener-%s", id)
}

func (p *Paladin) getContractListenerIDFromPaladinEventListenerName(name string) string {
	return strings.TrimPrefix(name, "ff-listener-")
}

func (p *Paladin) SubmitBatchPin(ctx context.Context, nsOpID, networkNamespace, signingKey string, batch *blockchain.BatchPin, location *fftypes.JSONAny) error {
	to, err := p.parseContractLocationPLDAddress(ctx, location)
	if err != nil {
		return err
	}

	method, input := p.buildBatchPinInput(batch)

	_, err = p.invokeContractMethod(ctx, to, signingKey, method, input, nil, nsOpID)
	return err
}

func (p *Paladin) SubmitNetworkAction(ctx context.Context, nsOpID, signingKey string, action core.NetworkActionType, location *fftypes.JSONAny) error {
	to, err := p.parseContractLocationPLDAddress(ctx, location)
	if err != nil {
		return err
	}

	method := networkActionMethodABI
	input := []interface{}{
		blockchain.FireFlyActionPrefix + action,
		"",
	}
	_, err = p.invokeContractMethod(ctx, to, signingKey, method, input, nil, nsOpID)
	return err
}

func (p *Paladin) AddFireflySubscription(ctx context.Context, namespace *core.Namespace, contract *blockchain.MultipartyContract, lastProtocolID string) (subID string, err error) {
	address, err := p.parseContractLocationPLDAddress(ctx, contract.Location)
	if err != nil {
		return "", err
	}

	version, err := p.GetNetworkVersion(ctx, contract.Location)
	if err != nil {
		return "", err
	}

	fromBlock, err := resolveFromBlock(ctx, contract.FirstEvent, lastProtocolID)
	if err != nil {
		return "", i18n.WrapError(ctx, err, coremsgs.MsgInvalidFromBlockNumber, contract.FirstEvent)
	}

	instanceUniqueHash := hex.EncodeToString(sha256.New().Sum([]byte(address.String())))[0:16]
	name := fmt.Sprintf("%s_%s_%s", namespace.Name, batchPinEventABI.Name, instanceUniqueHash)

	bel := &pldapi.BlockchainEventListener{
		Name: name,
		Sources: []pldapi.BlockchainEventListenerSource{
			{
				ABI:     []*abi.Entry{batchPinEventABI},
				Address: address,
			},
		},
		Options: pldapi.BlockchainEventListenerOptions{
			FromBlock: json.RawMessage(fmt.Sprintf("\"%s\"", fromBlock)),
		},
	}

	_, err = p.httpClient.PTX().CreateBlockchainEventListener(ctx, bel)
	if err != nil && !strings.Contains(err.Error(), "PD012246") {
		return "", i18n.WrapError(ctx, err, coremsgs.MsgPaladinConnectorRESTErr)
	}

	p.subs.AddSubscription(ctx, namespace, version, name, nil)

	if _, ok := p.eventLoops[name]; !ok {
		// kick off the event loop to listen for and process events
		sub, err := p.wsconn[namespace.Name].PTX().SubscribeBlockchainEvents(ctx, name)
		if err != nil {
			return "", i18n.WrapError(ctx, err, coremsgs.MsgPaladinConnectorRESTErr)
		}
		go p.fireflySubscriptionEventLoop(namespace.Name, name, sub)
	}

	return "", nil
}

func (p *Paladin) fireflySubscriptionEventLoop(namespace string, id string, sub rpcclient.Subscription) {
	l := log.L(p.ctx).
		WithField("role", "firefly-subscription").
		WithField("namespace", namespace).
		WithField("id", id)

	eventLoopCtx, eventLoopCancelCtx := context.WithCancel(p.ctx)
	eventLoopCtx = log.WithLogger(eventLoopCtx, l)
	p.eventLoops[id] = eventLoopCancelCtx

	// cancel is called if the event loop hits irrecoverable errors
	cancel := func() {
		l.Error("Event loop exiting. Terminating server!")
		// This cancels the context of the whole FireFly server!
		p.cancelCtx()
	}

	l.Debugf("Starting event loop for firefly subscription '%s:%s'", namespace, id)
	batchEventLoop(eventLoopCtx, l, cancel, sub, func(batch *pldapi.TransactionEventBatch) error {
		eventsToDispatch := make(common.EventsToDispatch)
		subInfo := p.subs.GetSubscription(id)
		if subInfo == nil {
			// this should never happen as the event loop is stopped before the subscription is removed
			// but handle it just in case- do not ack the events
			err := fmt.Errorf("no subscription found for ID %s", id)
			return err
		}
		for _, event := range batch.Events {
			// it's not possible to hit the error here as we've already unmarshalled to a paladin eth address
			location, _ := p.encodeContractLocation(eventLoopCtx, &Location{
				Address: event.Address.HexString(),
			})
			blockchainEvent := p.parseBlockchainEvent(event)

			authorAddress := blockchainEvent.Output.GetString("author")
			nsOrAction := blockchainEvent.Output.GetString("action")
			if nsOrAction == "" {
				nsOrAction = blockchainEvent.Output.GetString("namespace")
			}

			params := &common.BatchPinParams{
				UUIDs:      blockchainEvent.Output.GetString("uuids"),
				BatchHash:  blockchainEvent.Output.GetString("batchHash"),
				PayloadRef: blockchainEvent.Output.GetString("payloadRef"),
				Contexts:   blockchainEvent.Output.GetStringArray("contexts"),
				NsOrAction: nsOrAction,
			}

			formattedAuthorAddress, err := formatEthAddress(eventLoopCtx, authorAddress)
			if err != nil {
				l.Errorf("BatchPin event is not valid - bad from address: %s", authorAddress)
				return err
			}
			verifier := &core.VerifierRef{
				Type:  core.VerifierTypeEthAddress,
				Value: formattedAuthorAddress,
			}

			p.callbacks.PrepareBatchPinOrNetworkAction(eventLoopCtx, eventsToDispatch, subInfo, location, blockchainEvent, verifier, params)
		}

		err := p.callbacks.DispatchBlockchainEvents(eventLoopCtx, eventsToDispatch)
		if err != nil {
			l.Error("Failed to dispatch event batch")
			return err
		}
		return nil
	})
}

func (p *Paladin) RemoveFireflySubscription(ctx context.Context, subID string) {
	subInfo := p.subs.GetSubscription(subID)
	if subInfo == nil {
		log.L(ctx).Debugf("No subscription found for ID %s", subID)
		return
	}

	if cancel, ok := p.eventLoops[subID]; ok {
		cancel()
		delete(p.eventLoops, subID)
	}

	_, err := p.httpClient.PTX().DeleteBlockchainEventListener(ctx, subID)
	if err != nil && !strings.Contains(err.Error(), "PD012248") {
		log.L(ctx).Warnf("Failed to delete paladin blockchain event listener: %s", err)
	}
	p.subs.RemoveSubscription(ctx, subID)
}

func (p *Paladin) GetNetworkVersion(ctx context.Context, location *fftypes.JSONAny) (int, error) {
	ethLocation, err := p.parseContractLocation(ctx, location)
	if err != nil {
		return 0, err
	}

	cacheKey := "version:" + ethLocation.Address
	if cachedValue := p.cache.GetInt(cacheKey); cachedValue != 0 {
		return cachedValue, nil
	}

	version, err := p.queryNetworkVersion(ctx, ethLocation.Address)
	if err == nil {
		p.cache.SetInt(cacheKey, version)
	}
	return version, err
}

func (p *Paladin) queryNetworkVersion(ctx context.Context, address string) (version int, err error) {
	to, err := pldtypes.ParseEthAddress(address)
	if err != nil {
		return 0, err
	}
	res, err := p.queryContractMethod(ctx, to, "", networkVersionMethodABI, []interface{}{}, nil)
	if err != nil {
		return 0, err
	}
	output := &struct {
		Output interface{} `json:"0"`
	}{}

	if err = json.Unmarshal(res, output); err != nil {
		return 0, err
	}

	switch result := output.Output.(type) {
	case string:
		version, err = strconv.Atoi(result)
	default:
		err = i18n.NewError(ctx, coremsgs.MsgBadNetworkVersion, output.Output)
	}
	return version, err
}

func (p *Paladin) GetAndConvertDeprecatedContractConfig(ctx context.Context) (location *fftypes.JSONAny, fromBlock string, err error) {
	return nil, "", nil
}

func (p *Paladin) GetTransactionStatus(ctx context.Context, operation *core.Operation) (interface{}, error) {
	idempotencyKey := fmt.Sprintf("%s:%s", operation.Namespace, operation.ID)
	query := query.NewQueryBuilder().Limit(1).Equal("idempotencyKey", idempotencyKey).Query()
	txs, err := p.httpClient.PTX().QueryTransactionsFull(ctx, query)
	if err != nil {
		return nil, i18n.NewError(ctx, coremsgs.MsgPaladinConnectorRESTErr, err.Error())
	}
	if len(txs) == 0 {
		return nil, nil
	}
	// again this is returning the most native paladin structure we have as the most simple starting point
	return txs[0], nil
}

func (p *Paladin) ParseInterface(ctx context.Context, method *fftypes.FFIMethod, errors []*fftypes.FFIError) (interface{}, error) {
	methodABI, err := ffi2abi.ConvertFFIMethodToABI(ctx, method)
	if err != nil {
		return nil, err
	}
	methodInfo := &parsedFFIMethod{
		methodABI: methodABI,
		errorsABI: make([]*abi.Entry, len(errors)),
	}
	for i, ffiError := range errors {
		errorABI, err := ffi2abi.ConvertFFIErrorDefinitionToABI(ctx, &ffiError.FFIErrorDefinition)
		if err != nil {
			return nil, err
		}
		methodInfo.errorsABI[i] = errorABI
	}
	return methodInfo, nil
}

// Slightly ugly conversion from struct -> JSONObject which various parts of the generic framework require
// Errors are ignored as this should only be called with structs we have just unmarshalled so know will not error
func toJSONObject(v interface{}) fftypes.JSONObject {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	var j fftypes.JSONObject
	_ = json.Unmarshal(b, &j)
	return j
}

// All the functions below this comment are copied from the ethereum connector.
// While it would be better coding practice to make it common, it would extend the scope of this plugin beyond
// just its own package will makes later merges with OSS more challenging

var addressVerify = regexp.MustCompile("^[0-9a-f]{40}$")

type Location struct {
	Address string `json:"address"`
}

type parsedFFIMethod struct {
	methodABI *abi.Entry
	errorsABI []*abi.Entry
}

func resolveFromBlock(ctx context.Context, firstEvent, lastProtocolID string) (string, error) {
	// Parse the lastProtocolID if supplied
	var blockBeforeNewestEvent *uint64
	if len(lastProtocolID) > 0 {
		blockStr := strings.Split(lastProtocolID, "/")[0]
		parsedUint, err := strconv.ParseUint(blockStr, 10, 64)
		if err != nil {
			return "", i18n.NewError(ctx, coremsgs.MsgInvalidLastEventProtocolID, lastProtocolID)
		}
		if parsedUint > 0 {
			// We jump back on block from the last event, to minimize re-delivery while ensuring
			// we get all events since the last delivered (including subsequent events in the same block)
			parsedUint--
			blockBeforeNewestEvent = &parsedUint
		}
	}

	// If the user requested newest, then we use the last block number if we have one,
	// or we pass the request for newest down to the connector
	if firstEvent == "" || firstEvent == string(core.SubOptsFirstEventNewest) || firstEvent == "latest" {
		if blockBeforeNewestEvent != nil {
			return strconv.FormatUint(*blockBeforeNewestEvent, 10), nil
		}
		return "latest", nil
	}

	// Otherwise we expect to be able to parse the block, with "oldest" being the same as "0"
	if firstEvent == string(core.SubOptsFirstEventOldest) {
		firstEvent = "0"
	}
	blockNumber, err := strconv.ParseUint(firstEvent, 10, 64)
	if err != nil {
		return "", i18n.NewError(ctx, coremsgs.MsgInvalidFromBlockNumber, firstEvent)
	}
	// If the last event is already dispatched after this block, recreate the listener from that block
	if blockBeforeNewestEvent != nil && *blockBeforeNewestEvent > blockNumber {
		blockNumber = *blockBeforeNewestEvent
	}
	return strconv.FormatUint(blockNumber, 10), nil
}

type FFIGenerationInput struct {
	ABI *abi.ABI `json:"abi,omitempty"`
}

func (p *Paladin) GenerateFFI(ctx context.Context, generationRequest *fftypes.FFIGenerationRequest) (*fftypes.FFI, error) {
	var input FFIGenerationInput
	err := json.Unmarshal(generationRequest.Input.Bytes(), &input)
	if err != nil {
		return nil, i18n.WrapError(ctx, err, coremsgs.MsgFFIGenerationFailed, "unable to deserialize JSON as ABI")
	}
	if input.ABI == nil || len(*input.ABI) == 0 {
		return nil, i18n.NewError(ctx, coremsgs.MsgFFIGenerationFailed, "ABI is empty")
	}
	return ffi2abi.ConvertABIToFFI(ctx, generationRequest.Namespace, generationRequest.Name, generationRequest.Version, generationRequest.Description, input.ABI)
}

func (p *Paladin) NormalizeContractLocation(ctx context.Context, ntype blockchain.NormalizeType, location *fftypes.JSONAny) (*fftypes.JSONAny, error) {
	parsed, err := p.parseContractLocation(ctx, location)
	if err != nil {
		return nil, err
	}
	return p.encodeContractLocation(ctx, parsed)
}

func (p *Paladin) parseContractLocation(ctx context.Context, location *fftypes.JSONAny) (*Location, error) {
	ethLocation := Location{}
	if err := json.Unmarshal(location.Bytes(), &ethLocation); err != nil {
		return nil, i18n.NewError(ctx, coremsgs.MsgContractLocationInvalid, err)
	}
	if ethLocation.Address == "" {
		return nil, i18n.NewError(ctx, coremsgs.MsgContractLocationInvalid, "'address' not set")
	}
	return &ethLocation, nil
}

func (p *Paladin) parseContractLocationPLDAddress(ctx context.Context, location *fftypes.JSONAny) (*pldtypes.EthAddress, error) {
	parsed, err := p.parseContractLocation(ctx, location)
	if err != nil {
		return nil, err
	}
	address, err := pldtypes.ParseEthAddress(parsed.Address)
	if err != nil {
		return nil, i18n.NewError(ctx, coremsgs.MsgInvalidEthAddress)
	}
	return address, nil
}

func (p *Paladin) encodeContractLocation(ctx context.Context, location *Location) (result *fftypes.JSONAny, err error) {
	location.Address, err = formatEthAddress(ctx, location.Address)
	if err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(location)
	if err == nil {
		result = fftypes.JSONAnyPtrBytes(normalized)
	}
	return result, err
}

func formatEthAddress(ctx context.Context, key string) (string, error) {
	keyLower := strings.ToLower(key)
	keyNoHexPrefix := strings.TrimPrefix(keyLower, "0x")
	if addressVerify.MatchString(keyNoHexPrefix) {
		return "0x" + keyNoHexPrefix, nil
	}
	return "", i18n.NewError(ctx, coremsgs.MsgInvalidEthAddress)
}

func (p *Paladin) GetFFIParamValidator(ctx context.Context) (fftypes.FFIParamValidator, error) {
	return &ffi2abi.ParamValidator{}, nil
}

func (p *Paladin) GenerateEventSignature(ctx context.Context, event *fftypes.FFIEventDefinition) (string, error) {
	abi, err := ffi2abi.ConvertFFIEventDefinitionToABI(ctx, event)
	if err != nil {
		return "", err
	}
	signature := ffi2abi.ABIMethodToSignature(abi)
	indexedSignature := ABIMethodToIndexedSignature(abi)
	if indexedSignature != "" {
		signature = fmt.Sprintf("%s %s", signature, indexedSignature)
	}
	return signature, nil
}

func (p *Paladin) GenerateEventSignatureWithLocation(ctx context.Context, event *fftypes.FFIEventDefinition, location *fftypes.JSONAny) (string, error) {
	eventSignature, err := p.GenerateEventSignature(ctx, event)
	if err != nil {
		// new error here needed
		return "", err
	}

	// No location set
	if location == nil {
		return fmt.Sprintf("*:%s", eventSignature), nil
	}

	parsed, err := p.parseContractLocation(ctx, location)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s", parsed.Address, eventSignature), nil
}

func ABIMethodToIndexedSignature(abi *abi.Entry) string {
	if len(abi.Inputs) == 0 {
		return ""
	}
	positions := []string{}
	for i, param := range abi.Inputs {
		if param.Indexed {
			positions = append(positions, fmt.Sprint(i))
		}
	}

	// No indexed fields
	if len(positions) == 0 {
		return ""
	}

	return "[i=" + strings.Join(positions, ",") + "]"
}

func (p *Paladin) CheckOverlappingLocations(ctx context.Context, left *fftypes.JSONAny, right *fftypes.JSONAny) (bool, error) {
	if left == nil || right == nil {
		// No location on either side so overlapping
		return true, nil
	}

	parsedLeft, err := p.parseContractLocation(ctx, left)
	if err != nil {
		return false, err
	}

	parsedRight, err := p.parseContractLocation(ctx, right)
	if err != nil {
		return false, err
	}

	// For Ethereum just compared addresses
	return strings.EqualFold(parsedLeft.Address, parsedRight.Address), nil
}

func (p *Paladin) GenerateErrorSignature(ctx context.Context, errorDef *fftypes.FFIErrorDefinition) string {
	abi, err := ffi2abi.ConvertFFIErrorDefinitionToABI(ctx, errorDef)
	if err != nil {
		return ""
	}
	return ffi2abi.ABIMethodToSignature(abi)
}

func ethHexFormatB32(b *fftypes.Bytes32) string {
	if b == nil {
		return "0x0000000000000000000000000000000000000000000000000000000000000000"
	}
	return "0x" + hex.EncodeToString(b[0:32])
}

func (p *Paladin) buildBatchPinInput(batch *blockchain.BatchPin) (*abi.Entry, []interface{}) {
	ethHashes := make([]string, len(batch.Contexts))
	for i, v := range batch.Contexts {
		ethHashes[i] = ethHexFormatB32(v)
	}
	var uuids fftypes.Bytes32
	copy(uuids[0:16], (*batch.TransactionID)[:])
	copy(uuids[16:32], (*batch.BatchID)[:])

	method := batchPinMethodABI
	input := []interface{}{
		ethHexFormatB32(&uuids),
		ethHexFormatB32(batch.BatchHash),
		batch.BatchPayloadRef,
		ethHashes,
	}

	return method, input
}

// Paladin doesn't actually need the input to be ordered as an array- it could just use the map, but using an ordered array will allow for more code
// to be common with the ethereum connector
func (p *Paladin) prepareRequest(ctx context.Context, parsedMethod interface{}, input map[string]interface{}) (*parsedFFIMethod, []interface{}, error) {
	methodInfo, ok := parsedMethod.(*parsedFFIMethod)
	if !ok || methodInfo.methodABI == nil {
		return nil, nil, i18n.NewError(ctx, coremsgs.MsgUnexpectedInterfaceType, parsedMethod)
	}
	inputs := methodInfo.methodABI.Inputs
	orderedInput := make([]interface{}, len(inputs))
	for i, param := range inputs {
		orderedInput[i] = input[param.Name]
	}
	return methodInfo, orderedInput, nil
}

// Check if a method supports passing extra data via conformance to ERC5750.
// That is, check if the last method input is a "bytes" parameter.
func (p *Paladin) checkDataSupport(ctx context.Context, method *abi.Entry) error {
	if len(method.Inputs) > 0 {
		lastParam := method.Inputs[len(method.Inputs)-1]
		if lastParam.Type == "bytes" {
			return nil
		}
	}
	return i18n.NewError(ctx, coremsgs.MsgMethodDoesNotSupportPinning)
}
