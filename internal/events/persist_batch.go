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

package events

import (
	"context"

	"github.com/hyperledger/firefly/internal/log"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
)

func (em *eventManager) persistBatchFromBroadcast(ctx context.Context /* db TX context*/, batch *fftypes.Batch, onchainHash *fftypes.Bytes32) (valid bool, err error) {

	if !onchainHash.Equals(batch.Hash) {
		log.L(ctx).Errorf("Invalid batch '%s'. Hash in batch '%s' does not match transaction hash '%s'", batch.ID, batch.Hash, onchainHash)
		return false, nil // This is not retryable. skip this batch
	}

	_, valid, err = em.persistBatch(ctx, batch)
	return valid, err
}

// persistBatch performs very simple validation on each message/data element (hashes) and either persists
// or discards them. Errors are returned only in the case of database failures, which should be retried.
func (em *eventManager) persistBatch(ctx context.Context /* db TX context*/, batch *fftypes.Batch) (persistedBatch *fftypes.BatchPersisted, valid bool, err error) {
	l := log.L(ctx)

	if batch.ID == nil || batch.Payload.TX.ID == nil {
		l.Errorf("Invalid batch '%s'. Missing ID or transaction ID (%v)", batch.ID, batch.Payload.TX.ID)
		return nil, false, nil // This is not retryable. skip this batch
	}

	switch batch.Payload.TX.Type {
	case fftypes.TransactionTypeBatchPin:
	case fftypes.TransactionTypeUnpinned:
	default:
		l.Errorf("Invalid batch '%s'. Invalid transaction type: %s", batch.ID, batch.Payload.TX.Type)
		return nil, false, nil // This is not retryable. skip this batch
	}

	// Set confirmed on the batch (the messages should not be confirmed at this point - that's the aggregator's job)
	persistedBatch, _ = batch.Confirmed()
	manifestHash := fftypes.HashString(persistedBatch.Manifest.String())

	// Verify the hash calculation.
	if !manifestHash.Equals(batch.Hash) {
		// To cope with existing batches written by v0.13 and older environments, we have to do a more expensive
		// hashing of the whole payload before we reject.
		if batch.Payload.Hash().Equals(batch.Hash) {
			l.Infof("Persisting migrated batch '%s'. Hash is a payload hash: %s", batch.ID, batch.Hash)
		} else {
			l.Errorf("Invalid batch '%s'. Hash does not match payload. Found=%s Expected=%s", batch.ID, manifestHash, batch.Hash)
			return nil, false, nil // This is not retryable. skip this batch
		}
	}

	// Upsert the batch
	err = em.database.UpsertBatch(ctx, persistedBatch)
	if err != nil {
		if err == database.HashMismatch {
			l.Errorf("Invalid batch '%s'. Batch hash mismatch with existing record", batch.ID)
			return nil, false, nil // This is not retryable. skip this batch
		}
		l.Errorf("Failed to insert batch '%s': %s", batch.ID, err)
		return nil, false, err // a persistence failure here is considered retryable (so returned)
	}

	valid, err = em.persistBatchContent(ctx, batch)
	if err != nil || !valid {
		return nil, valid, err
	}
	return persistedBatch, valid, err
}

func (em *eventManager) persistBatchContent(ctx context.Context, batch *fftypes.Batch) (valid bool, err error) {

	optimization := em.getOptimization(ctx, batch)

	// Insert the data entries
	dataByID := make(map[fftypes.UUID]*fftypes.Data)
	for i, data := range batch.Payload.Data {
		if valid, err = em.persistBatchData(ctx, batch, i, data, optimization); !valid || err != nil {
			return valid, err
		}
		dataByID[*data.ID] = data
	}

	// Insert the message entries
	for i, msg := range batch.Payload.Messages {
		if valid, err = em.persistBatchMessage(ctx, batch, i, msg, optimization); !valid || err != nil {
			return valid, err
		}
		dataInBatch := true
		msgData := make(fftypes.DataArray, len(msg.Data))
		for di, dataRef := range msg.Data {
			msgData[di] = dataByID[*dataRef.ID]
			if msgData[di] == nil || !msgData[di].Hash.Equals(dataRef.Hash) {
				log.L(ctx).Debugf("Message '%s' in batch '%s' - data not in-line in batch id='%s' hash='%s'", msg.Header.ID, batch.ID, dataRef.ID, dataRef.Hash)
				dataInBatch = false
				break
			}
		}
		if dataInBatch {
			// We can push the complete message into the cache straight away
			em.data.UpdateMessageCache(msg, msgData)
		}
	}

	return true, nil
}

func (em *eventManager) getOptimization(ctx context.Context, batch *fftypes.Batch) database.UpsertOptimization {
	localNode := em.ni.GetNodeUUID(ctx)
	if batch.Node == nil {
		// This is from a node that hasn't yet completed registration, so we can't optimize
		return database.UpsertOptimizationSkip
	} else if localNode != nil && localNode.Equals(batch.Node) {
		// We sent the batch, so we should already have all the messages and data locally - optimize the DB operations for that
		return database.UpsertOptimizationExisting
	}
	// We didn't send the batch, so all the data should be new - optimize the DB operations for that
	return database.UpsertOptimizationNew
}

func (em *eventManager) persistBatchData(ctx context.Context /* db TX context*/, batch *fftypes.Batch, i int, data *fftypes.Data, optimization database.UpsertOptimization) (bool, error) {
	return em.persistReceivedData(ctx, i, data, "batch", batch.ID, optimization)
}

func (em *eventManager) persistReceivedData(ctx context.Context /* db TX context*/, i int, data *fftypes.Data, mType string, mID *fftypes.UUID, optimization database.UpsertOptimization) (bool, error) {

	l := log.L(ctx)
	l.Tracef("%s '%s' data %d: %+v", mType, mID, i, data)

	if data == nil {
		l.Errorf("null data entry %d in %s '%s'", i, mType, mID)
		return false, nil // skip data entry
	}

	hash, err := data.CalcHash(ctx)
	if err != nil {
		log.L(ctx).Errorf("Invalid data entry %d in %s '%s': %s", i, mType, mID, err)
		return false, nil //
	}
	if data.Hash == nil || *data.Hash != *hash {
		log.L(ctx).Errorf("Invalid data entry %d in %s '%s': Hash=%v Expected=%v", i, mType, mID, data.Hash, hash)
		return false, nil // skip data entry
	}

	// Insert the data, ensuring the hash doesn't change
	if err := em.database.UpsertData(ctx, data, optimization); err != nil {
		if err == database.HashMismatch {
			log.L(ctx).Errorf("Invalid data entry %d in %s '%s'. Hash mismatch with existing record with same UUID '%s' Hash=%s", i, mType, mID, data.ID, data.Hash)
			return false, nil // This is not retryable. skip this data entry
		}
		log.L(ctx).Errorf("Failed to insert data entry %d in %s '%s': %s", i, mType, mID, err)
		return false, err // a persistence failure here is considered retryable (so returned)
	}

	return true, nil
}

func (em *eventManager) persistBatchMessage(ctx context.Context /* db TX context*/, batch *fftypes.Batch, i int, msg *fftypes.Message, optimization database.UpsertOptimization) (bool, error) {
	if msg != nil {
		if msg.Header.Author != batch.Author || msg.Header.Key != batch.Key {
			log.L(ctx).Errorf("Mismatched key/author '%s'/'%s' on message entry %d in batch '%s'", msg.Header.Key, msg.Header.Author, i, batch.ID)
			return false, nil // skip entry
		}
		msg.BatchID = batch.ID
	}

	return em.persistReceivedMessage(ctx, i, msg, "batch", batch.ID, optimization)
}

func (em *eventManager) persistReceivedMessage(ctx context.Context /* db TX context*/, i int, msg *fftypes.Message, mType string, mID *fftypes.UUID, optimization database.UpsertOptimization) (bool, error) {
	l := log.L(ctx)
	l.Tracef("%s '%s' message %d: %+v", mType, mID, i, msg)

	if msg == nil {
		l.Errorf("null message entry %d in %s '%s'", i, mType, mID)
		return false, nil // skip entry
	}

	err := msg.Verify(ctx)
	if err != nil {
		l.Errorf("Invalid message entry %d in %s '%s': %s", i, mType, mID, err)
		return false, nil // skip message entry
	}

	// Insert the message, ensuring the hash doesn't change.
	// We do not mark it as confirmed at this point, that's the job of the aggregator.
	msg.State = fftypes.MessageStatePending
	if err = em.database.UpsertMessage(ctx, msg, optimization); err != nil {
		if err == database.HashMismatch {
			l.Errorf("Invalid message entry %d in %s '%s'. Hash mismatch with existing record with same UUID '%s' Hash=%s", i, mType, mID, msg.Header.ID, msg.Hash)
			return false, nil // This is not retryable. skip this data entry
		}
		l.Errorf("Failed to insert message entry %d in %s '%s': %s", i, mType, mID, err)
		return false, err // a persistence failure here is considered retryable (so returned)
	}

	return true, nil
}
