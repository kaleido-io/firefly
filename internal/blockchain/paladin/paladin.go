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
	"fmt"
	"regexp"
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
	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/internal/metrics"
	"github.com/hyperledger/firefly/pkg/blockchain"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
	"github.com/sirupsen/logrus"
)

var addressVerify = regexp.MustCompile("^[0-9a-f]{40}$")

type Location struct {
	Address string `json:"address"`
}

type parsedFFIMethod struct {
	methodABI *abi.Entry
	errorsABI []*abi.Entry
}

type Paladin struct {
	ctx              context.Context
	cancelCtx        context.CancelFunc
	metrics          metrics.Manager
	capabilities     *blockchain.Capabilities
	callbacks        common.BlockchainCallbacks
	httpClientConfig pldconf.HTTPClientConfig
	httpClient       pldclient.PaladinClient
	// this looks like we have two things of the same type but it needs to be
	// this way because the http client doesn't work for creating a working WSClient
	pldClient      pldclient.PaladinClient
	wsClientConfig pldconf.WSClientConfig
	wsconn         map[string]pldclient.PaladinWSClient
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
	return nil
}

func (p *Paladin) StartNamespace(ctx context.Context, namespace string) error {
	// Websocket Client per Namespace
	log.L(p.ctx).Debugf("Starting namespace: %s", namespace)

	// try to start the receipt listener
	_, err := p.httpClient.PTX().StartReceiptListener(ctx, namespace)
	if err != nil {
		if strings.Contains(err.Error(), "PD012238") {
			_, err = p.httpClient.PTX().CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
				Name: namespace,
			})
		}
		if err != nil {
			return err
		}
	}

	p.wsconn[namespace], err = p.pldClient.WebSocket(ctx, &p.wsClientConfig)
	if err != nil {
		return err
	}

	sub, err := p.wsconn[namespace].PTX().SubscribeReceipts(ctx, namespace)
	if err != nil {
		return err
	}

	// Run an event loop to fetch receipts and update an operation
	go p.batchEventLoop(namespace, sub)
	return nil
}

func (p *Paladin) batchEventLoop(namespace string, sub rpcclient.Subscription) {
	l := log.L(p.ctx).WithField("role", "event-loop").WithField("namespace", namespace)
	defer p.wsconn[namespace].Close()
	ctx := log.WithLogger(p.ctx, l)
	l.Debugf("Starting event loop for namespace '%s'", namespace)
	for {
		select {
		case <-ctx.Done():
			l.Debugf("Event loop exiting (context cancelled)")
			return
		case subNotification, ok := <-sub.Notifications():
			if !ok {
				// This cancels the context of the whole plugin!
				p.exitLoopWithError(l, nil, "Unable to read from subscription")
				return
			}

			// Handle websocket event
			var batch pldapi.TransactionReceiptBatch
			err := json.Unmarshal(subNotification.GetResult(), &batch)
			if err != nil {
				p.exitLoopWithError(l, err, "Unable to unmarshall subscription")
				return
			}

			updates := []*core.OperationUpdate{}
			// if there is an error processing any of the receipts we need to exit the loop and terminate the server
			// we might not need to be so heavy handed if paladin will resend the batch on a nack- (although not clear
			// why we would expect a different result the next time around)
			for _, receipt := range batch.Receipts {
				fmt.Printf("%v", receipt.TransactionReceipt.ID)
				// For now, we need to get the transaction to get the idempotency Key
				// Might be fixed through https://github.com/LF-Decentralized-Trust-labs/paladin/issues/551
				tx, err := p.httpClient.PTX().GetTransactionFull(ctx, receipt.TransactionReceipt.ID)
				if err != nil {
					p.exitLoopWithError(l, err, fmt.Sprintf("Receipt cannot be processed - failed to get transaction by ID: %+v", receipt))
					return

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

				// We can probably wrangle it into this format but lets start by taking
				// the paladin receipt as it and seeing whether this is ok

				// Slightly ugly conversion from Receipt -> JSONObject which the generic OperationUpdate() function requires
				var output fftypes.JSONObject
				// there will not be an error as we only just unmarshalled receipt
				obj, _ := json.Marshal(receipt)
				_ = json.Unmarshal(obj, &output)
				updates = append(updates, &core.OperationUpdate{
					Plugin:         p.Name(),
					NamespacedOpID: nsOpID,
					Status:         status,
					BlockchainTXID: receipt.TransactionHash.String(),
					ErrorMessage:   receipt.FailureMessage,
					Output:         output,
				})
			}

			if len(updates) > 0 {
				// We have a batch of operation updates
				err := p.callbacks.BulkOperationUpdates(ctx, namespace, updates)
				if err != nil {
					p.exitLoopWithError(l, err, fmt.Sprintf("Failed to commit batch updates: %s", err.Error()))
					return
				}
			}

			l.Debug("All events from websocket handsled")

			// We only send this ACK once we have committed all the DB writes
			// Which is done as part of BulkOperationUpdates
			err = subNotification.Ack(ctx)
			if err != nil {
				p.exitLoopWithError(l, err, "Failed to ack batch receipt")
				return
			}
		}
	}
}

func (p *Paladin) exitLoopWithError(l *logrus.Entry, err error, message string) {
	if message != "" {
		l.Error(message)
	}
	l.Errorf("Event loop exiting (%s). Terminating server!", err)
	p.cancelCtx()
}

func (p *Paladin) StopNamespace(ctx context.Context, namespace string) error {
	_, err := p.httpClient.PTX().StopReceiptListener(ctx, namespace)
	if err != nil {
		// just log the error- it doesn't stop anything from working if we don't manage to stop the listener
		log.L(p.ctx).Warnf("Failed to stop paladin receipt listener for namespace: %s", namespace)
	}

	wsconn, ok := p.wsconn[namespace]
	if ok {
		wsconn.Close()
	}
	delete(p.wsconn, namespace)

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

func (p *Paladin) ResolveSigningKey(ctx context.Context, keyRef string, intent blockchain.ResolveKeyIntent) (string, error) {
	// TODO how will the intent get passed through to the paladin signing module?
	return p.httpClient.PTX().ResolveVerifier(ctx, keyRef, "ecdsa:secp256k1", verifiers.ETH_ADDRESS)
}

func (p *Paladin) SubmitBatchPin(ctx context.Context, nsOpID, networkNamespace, signingKey string, batch *blockchain.BatchPin, location *fftypes.JSONAny) error {
	// Not applicable for now
	return nil
}

func (p *Paladin) SubmitNetworkAction(ctx context.Context, nsOpID, signingKey string, action core.NetworkActionType, location *fftypes.JSONAny) error {
	// Not applicable for now
	return nil
}

func (p *Paladin) DeployContract(ctx context.Context, nsOpID, signingKey string, definition, contract *fftypes.JSONAny, input []interface{}, options map[string]interface{}) (submissionRejected bool, err error) {
	if p.metrics.IsMetricsEnabled() {
		p.metrics.BlockchainContractDeployment()
	}

	bytecode, err := tktypes.ParseHexBytes(ctx, contract.AsString())
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
			Data:           tktypes.JSONString(input),
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
	_, err := p.prepareRequest(ctx, parsedMethod)
	return err
}

func (p *Paladin) prepareRequest(ctx context.Context, parsedMethod interface{}) (*parsedFFIMethod, error) {
	methodInfo, ok := parsedMethod.(*parsedFFIMethod)
	if !ok || methodInfo.methodABI == nil {
		return nil, i18n.NewError(ctx, coremsgs.MsgUnexpectedInterfaceType, parsedMethod)
	}
	return methodInfo, nil
}

func (p *Paladin) setOptions(ctx context.Context, options map[string]interface{}, tx *pldapi.TransactionInput) error {
	var err error
	if options["gasLimit"] != nil {
		gasLimit, err := tktypes.ParseHexUint64(ctx, options["gasLimit"].(string))
		if err != nil {
			return err
		}
		tx.Gas = &gasLimit
	}

	if options["gasPrice"] != nil {
		tx.GasPrice, err = tktypes.ParseHexUint256(ctx, options["gasPrice"].(string))
		if err != nil {
			return err
		}
	}

	if options["maxFeePerGas"] != nil {
		tx.MaxFeePerGas, err = tktypes.ParseHexUint256(ctx, options["maxFeePerGas"].(string))
		if err != nil {
			return err
		}
	}

	if options["maxPriorityFeePerGas"] != nil {
		tx.MaxPriorityFeePerGas, err = tktypes.ParseHexUint256(ctx, options["maxPriorityFeePerGas"].(string))
		if err != nil {
			return err
		}
	}

	if options["value"] != nil {
		tx.Value, err = tktypes.ParseHexUint256(ctx, options["value"].(string))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Paladin) InvokeContract(ctx context.Context, nsOpID, signingKey string, location *fftypes.JSONAny, parsedMethod interface{}, input map[string]interface{}, options map[string]interface{}, batch *blockchain.BatchPin) (submissionRejected bool, err error) {
	to, err := tktypes.ParseEthAddress(location.AsString())
	if err != nil {
		return true, err
	}

	methodInfo, err := p.prepareRequest(ctx, parsedMethod)
	if err != nil {
		return true, err
	}

	if p.metrics.IsMetricsEnabled() {
		p.metrics.BlockchainTransaction(to.String(), methodInfo.methodABI.Name)
	}

	tx := &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{
			IdempotencyKey: nsOpID,
			Type:           pldapi.TransactionTypePublic.Enum(),
			From:           signingKey,
			To:             to,
			Data:           tktypes.JSONString(input),
			Function:       methodInfo.methodABI.Name,
		},
		ABI: []*abi.Entry{methodInfo.methodABI},
	}

	err = p.setOptions(ctx, options, tx)
	if err != nil {
		return true, err
	}

	_, err = p.httpClient.PTX().SendTransaction(ctx, tx)

	return false, err
}

func (p *Paladin) QueryContract(ctx context.Context, signingKey string, location *fftypes.JSONAny, parsedMethod interface{}, input map[string]interface{}, options map[string]interface{}) (interface{}, error) {
	to, err := tktypes.ParseEthAddress(location.AsString())
	if err != nil {
		return nil, err
	}

	methodInfo, err := p.prepareRequest(ctx, parsedMethod)
	if err != nil {
		return nil, err
	}

	if p.metrics.IsMetricsEnabled() {
		p.metrics.BlockchainQuery(to.String(), methodInfo.methodABI.Name)
	}

	tx := &pldapi.TransactionCall{
		TransactionInput: pldapi.TransactionInput{
			TransactionBase: pldapi.TransactionBase{
				Type:     pldapi.TransactionTypePublic.Enum(),
				From:     signingKey,
				To:       to,
				Data:     tktypes.JSONString(input),
				Function: methodInfo.methodABI.Name,
			},
			ABI: []*abi.Entry{methodInfo.methodABI},
		},
	}

	err = p.setOptions(ctx, options, &tx.TransactionInput)
	if err != nil {
		return nil, err
	}

	return p.httpClient.PTX().Call(ctx, tx)
}

func (p *Paladin) AddContractListener(ctx context.Context, subscription *core.ContractListener, lastProtocolID string) error {
	// Not supported for now
	return nil
}

func (p *Paladin) DeleteContractListener(ctx context.Context, subscription *core.ContractListener, okNotFound bool) error {
	// Not supported for now
	return nil
}

func (p *Paladin) GetContractListenerStatus(ctx context.Context, namespace, subID string, okNotFound bool) (bool, interface{}, core.ContractListenerStatus, error) {
	// Not supported for now
	return false, nil, "", nil
}

func (p *Paladin) GetFFIParamValidator(ctx context.Context) (fftypes.FFIParamValidator, error) {
	return &ffi2abi.ParamValidator{}, nil
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

func (p *Paladin) GenerateEventSignature(ctx context.Context, event *fftypes.FFIEventDefinition) (string, error) {
	return "", nil
}

func (p *Paladin) GenerateEventSignatureWithLocation(ctx context.Context, event *fftypes.FFIEventDefinition, location *fftypes.JSONAny) (string, error) {
	return "", nil
}

func (p *Paladin) CheckOverlappingLocations(ctx context.Context, left *fftypes.JSONAny, right *fftypes.JSONAny) (bool, error) {
	return false, nil
}

func (p *Paladin) GenerateErrorSignature(ctx context.Context, errorDef *fftypes.FFIErrorDefinition) string {
	return ""
}

func (p *Paladin) GetNetworkVersion(ctx context.Context, location *fftypes.JSONAny) (int, error) {
	return 0, nil
}

func (p *Paladin) GetAndConvertDeprecatedContractConfig(ctx context.Context) (location *fftypes.JSONAny, fromBlock string, err error) {
	return nil, "", nil
}

func (p *Paladin) AddFireflySubscription(ctx context.Context, namespace *core.Namespace, contract *blockchain.MultipartyContract, lastProtocolID string) (subID string, err error) {
	return "", nil
}

func (p *Paladin) RemoveFireflySubscription(ctx context.Context, subID string) {}

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
	// TODO: again this is returning the most native paladin structure we have as the most simple starting point, we might need to do some conversion
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
