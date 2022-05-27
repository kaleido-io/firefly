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

package assets

import (
	"context"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/internal/txcommon"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/hyperledger/firefly/pkg/database"
)

func (am *assetManager) CreateTokenPool(ctx context.Context, ns string, pool *core.TokenPool, waitConfirm bool) (*core.TokenPool, error) {
	db, err := am.namespace.GetDatabasePlugin(ctx, ns)
	if err != nil {
		return nil, err
	}

	if err := am.data.VerifyNamespaceExists(ctx, ns); err != nil {
		return nil, err
	}
	if err := core.ValidateFFNameFieldNoUUID(ctx, pool.Name, "name"); err != nil {
		return nil, err
	}
	if existing, err := db.GetTokenPool(ctx, ns, pool.Name); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, i18n.NewError(ctx, coremsgs.MsgTokenPoolDuplicate, pool.Name)
	}
	pool.ID = fftypes.NewUUID()
	pool.Namespace = ns

	if pool.Connector == "" {
		connector, err := am.getDefaultTokenConnector(ctx, ns)
		if err != nil {
			return nil, err
		}
		pool.Connector = connector
	}

	pool.Key, err = am.identity.NormalizeSigningKey(ctx, pool.Key, am.keyNormalization)
	if err != nil {
		return nil, err
	}
	return am.createTokenPoolInternal(ctx, pool, waitConfirm)
}

func (am *assetManager) createTokenPoolInternal(ctx context.Context, pool *core.TokenPool, waitConfirm bool) (*core.TokenPool, error) {
	db, err := am.namespace.GetDatabasePlugin(ctx, pool.Namespace)
	if err != nil {
		return nil, err
	}

	plugin, err := am.selectTokenPlugin(ctx, pool.Connector, pool.Namespace)
	if err != nil {
		return nil, err
	}

	if waitConfirm {
		return am.syncasync.WaitForTokenPool(ctx, pool.Namespace, pool.ID, func(ctx context.Context) error {
			_, err := am.createTokenPoolInternal(ctx, pool, false)
			return err
		})
	}

	var op *core.Operation
	err = db.RunAsGroup(ctx, func(ctx context.Context) (err error) {
		txid, err := am.txHelper.SubmitNewTransaction(ctx, pool.Namespace, core.TransactionTypeTokenPool)
		if err != nil {
			return err
		}

		pool.TX.ID = txid
		pool.TX.Type = core.TransactionTypeTokenPool

		op = core.NewOperation(
			plugin,
			pool.Namespace,
			txid,
			core.OpTypeTokenCreatePool)
		if err = txcommon.AddTokenPoolCreateInputs(op, pool); err == nil {
			err = db.InsertOperation(ctx, op)
		}
		return err
	})
	if err != nil {
		return nil, err
	}

	_, err = am.operations.RunOperation(ctx, opCreatePool(op, pool))
	return pool, err
}

func (am *assetManager) ActivateTokenPool(ctx context.Context, pool *core.TokenPool) error {
	db, err := am.namespace.GetDatabasePlugin(ctx, pool.Namespace)
	if err != nil {
		return err
	}

	plugin, err := am.selectTokenPlugin(ctx, pool.Connector, pool.Namespace)
	if err != nil {
		return err
	}

	var op *core.Operation
	err = db.RunAsGroup(ctx, func(ctx context.Context) (err error) {
		fb := database.OperationQueryFactory.NewFilter(ctx)
		filter := fb.And(
			fb.Eq("tx", pool.TX.ID),
			fb.Eq("type", core.OpTypeTokenActivatePool),
		)
		if existing, _, err := db.GetOperations(ctx, filter); err != nil {
			return err
		} else if len(existing) > 0 {
			log.L(ctx).Debugf("Dropping duplicate token pool activation request for pool %s", pool.ID)
			return nil
		}

		op = core.NewOperation(
			plugin,
			pool.Namespace,
			pool.TX.ID,
			core.OpTypeTokenActivatePool)
		txcommon.AddTokenPoolActivateInputs(op, pool.ID)
		return db.InsertOperation(ctx, op)
	})
	if err != nil || op == nil {
		return err
	}

	_, err = am.operations.RunOperation(ctx, opActivatePool(op, pool))
	return err
}

func (am *assetManager) GetTokenPools(ctx context.Context, ns string, filter database.AndFilter) ([]*core.TokenPool, *database.FilterResult, error) {
	db, err := am.namespace.GetDatabasePlugin(ctx, ns)
	if err != nil {
		return nil, nil, err
	}

	if err := core.ValidateFFNameField(ctx, ns, "namespace"); err != nil {
		return nil, nil, err
	}
	return db.GetTokenPools(ctx, am.scopeNS(ns, filter))
}

func (am *assetManager) GetTokenPool(ctx context.Context, ns, connector, poolName string) (*core.TokenPool, error) {
	db, err := am.namespace.GetDatabasePlugin(ctx, ns)
	if err != nil {
		return nil, err
	}

	if _, err := am.selectTokenPlugin(ctx, connector, ns); err != nil {
		return nil, err
	}
	if err := core.ValidateFFNameField(ctx, ns, "namespace"); err != nil {
		return nil, err
	}
	if err := core.ValidateFFNameFieldNoUUID(ctx, poolName, "name"); err != nil {
		return nil, err
	}
	pool, err := db.GetTokenPool(ctx, ns, poolName)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, i18n.NewError(ctx, coremsgs.Msg404NotFound)
	}
	return pool, nil
}

func (am *assetManager) GetTokenPoolByNameOrID(ctx context.Context, ns, poolNameOrID string) (*core.TokenPool, error) {
	if err := core.ValidateFFNameField(ctx, ns, "namespace"); err != nil {
		return nil, err
	}

	db, err := am.namespace.GetDatabasePlugin(ctx, ns)
	if err != nil {
		return nil, err
	}

	var pool *core.TokenPool

	poolID, err := fftypes.ParseUUID(ctx, poolNameOrID)
	if err != nil {
		if err := core.ValidateFFNameField(ctx, poolNameOrID, "name"); err != nil {
			return nil, err
		}
		if pool, err = db.GetTokenPool(ctx, ns, poolNameOrID); err != nil {
			return nil, err
		}
	} else if pool, err = db.GetTokenPoolByID(ctx, poolID); err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, i18n.NewError(ctx, coremsgs.Msg404NotFound)
	}
	return pool, nil
}
