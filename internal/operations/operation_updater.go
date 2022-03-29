// Copyright © 2022 Kaleido, Inc.
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

package operations

import (
	"context"
	"database/sql/driver"
	"time"

	"github.com/hyperledger/firefly/internal/config"
	"github.com/hyperledger/firefly/internal/i18n"
	"github.com/hyperledger/firefly/internal/log"
	"github.com/hyperledger/firefly/internal/retry"
	"github.com/hyperledger/firefly/internal/txcommon"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
)

type NewMessage struct {
	Message *fftypes.MessageInOut
	AllData fftypes.DataArray
	NewData fftypes.DataArray
}

// OperationUpdate is dispatched asynchronously to perform an update.
type OperationUpdate struct {
	ID             *fftypes.UUID
	TxState        fftypes.OpStatus
	BlockchainTXID string
	ErrorMessage   string
	Output         fftypes.JSONObject
	Event          *fftypes.Event
}

type operationUpdaterBatch struct {
	updates        []*OperationUpdate
	timeoutContext context.Context
	timeoutCancel  func()
}

// operationUpdater
type operationUpdater struct {
	ctx         context.Context
	cancelFunc  func()
	database    database.Plugin
	txHelper    txcommon.Helper
	workQueue   chan *OperationUpdate
	workersDone []chan struct{}
	conf        operationUpdaterConf
	closed      bool
	retry       *retry.Retry
}

type operationUpdaterConf struct {
	workerCount  int
	batchTimeout time.Duration
	maxInserts   int
}

func newOperationUpdater(ctx context.Context, di database.Plugin) *operationUpdater {
	ou := &operationUpdater{
		database: di,
		conf: operationUpdaterConf{
			workerCount:  config.GetInt(config.OpUpdateWorkerCount),
			batchTimeout: config.GetDuration(config.OpUpdateWorkerBatchTimeout),
			maxInserts:   config.GetInt(config.OpUpdateWorkerBatchMaxInserts),
		},
		retry: &retry.Retry{
			InitialDelay: config.GetDuration(config.OpUpdateRetryInitDelay),
			MaximumDelay: config.GetDuration(config.OpUpdateRetryMaxDelay),
			Factor:       config.GetFloat64(config.OpUpdateRetryFactor),
		},
	}
	ou.ctx, ou.cancelFunc = context.WithCancel(ctx)
	if !di.Capabilities().Concurrency {
		log.L(ctx).Infof("Database plugin not configured for concurrency. Batched operation updates disabled")
		ou.conf.workerCount = 0
	}
	return ou
}

func (ou *operationUpdater) UpdateEvent(ctx context.Context, update *OperationUpdate) error {
	if ou.conf.workerCount > 0 {
		select {
		case ou.workQueue <- update:
		case <-ou.ctx.Done():
			return i18n.NewError(ctx, i18n.MsgContextCanceled)
		}
		return nil
	}
	// Otherwise do it in-line on this context
	return ou.database.RunAsGroup(ctx, func(ctx context.Context) error {
		return ou.operationUpdateCtx(ctx, []*OperationUpdate{update})
	})
}

func (ou *operationUpdater) updaterLoop(index int) {
	defer close(ou.workersDone[index])

	var batch *operationUpdaterBatch
	var insertCount int
	for !ou.closed {
		var timeoutContext context.Context
		var timedOut bool
		if batch != nil {
			timeoutContext = batch.timeoutContext
		} else {
			timeoutContext = ou.ctx
		}
		select {
		case work := <-ou.workQueue:
			if batch == nil {
				batch = &operationUpdaterBatch{}
				batch.timeoutContext, batch.timeoutCancel = context.WithTimeout(ou.ctx, ou.conf.batchTimeout)
				insertCount = 0
			}
			batch.updates = append(batch.updates, work)
			insertCount++
			if work.Event != nil {
				insertCount++
			}
		case <-timeoutContext.Done():
			timedOut = true
		}

		if batch != nil && (timedOut || insertCount >= ou.conf.maxInserts) {
			batch.timeoutCancel()
			err := ou.retry.Do(ou.ctx, "operation batch update", func(attempt int) (retry bool, err error) {
				return true, ou.database.RunAsGroup(ou.ctx, func(ctx context.Context) error {
					return ou.operationUpdateCtx(ctx, batch.updates)
				})
			})
			if err != nil {
				log.L(ou.ctx).Debugf("Operation update worker exiting: %s", err)
				return
			}
			batch = nil
		}
	}
}

func (ou *operationUpdater) operationUpdateCtx(ctx context.Context, updates []*OperationUpdate) error {

	// Get all the operations that match
	opIDs := make([]driver.Value, len(updates))
	for idx, update := range updates {
		opIDs[idx] = update.ID
	}
	opFilter := database.OperationQueryFactory.NewFilter(ctx).In("id", opIDs)
	ops, _, err := ou.database.GetOperations(ctx, opFilter)
	if err != nil {
		return err
	}

	// Get all the transactions for these operations
	txIDs := make([]driver.Value, 0, len(ops))
	for _, op := range ops {
		if op.Transaction != nil {
			txIDs = append(txIDs, op.Transaction)
		}
	}
	txFilter := database.TransactionQueryFactory.NewFilter(ctx).In("id", txIDs)
	transactions, _, err := ou.database.GetTransactions(ctx, txFilter)
	if err != nil {
		return err
	}

	op, err := ou.database.GetOperationByID(ctx, operationID)
	if err != nil || op == nil {
		log.L(ctx).Warnf("Operation update '%s' ignored, as it was not submitted by this node", operationID)
		return nil
	}

	if err := ou.database.ResolveOperation(ctx, op.ID, txState, errorMessage, opOutput); err != nil {
		return err
	}

	if err := ou.database.InsertEvent(ctx, event); err != nil {
		return err
	}

	return ou.txHelper.AddBlockchainTX(ctx, op.Transaction, blockchainTXID)
}

func (ou *operationUpdater) close() {
	if !ou.closed {
		ou.closed = true
		ou.cancelFunc()
		for _, workerDone := range ou.workersDone {
			<-workerDone
		}
	}
}
