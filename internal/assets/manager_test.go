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
	"fmt"
	"testing"

	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/internal/txcommon"
	"github.com/hyperledger/firefly/mocks/broadcastmocks"
	"github.com/hyperledger/firefly/mocks/databasemocks"
	"github.com/hyperledger/firefly/mocks/datamocks"
	"github.com/hyperledger/firefly/mocks/identitymanagermocks"
	"github.com/hyperledger/firefly/mocks/metricsmocks"
	"github.com/hyperledger/firefly/mocks/namespacemocks"
	"github.com/hyperledger/firefly/mocks/operationmocks"
	"github.com/hyperledger/firefly/mocks/privatemessagingmocks"
	"github.com/hyperledger/firefly/mocks/syncasyncmocks"
	"github.com/hyperledger/firefly/mocks/tokenmocks"
	"github.com/hyperledger/firefly/mocks/txcommonmocks"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/tokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTestAssets(t *testing.T) (*assetManager, func()) {
	return newTestAssetsCommon(t, false)
}

func newTestAssetsWithMetrics(t *testing.T) (*assetManager, func()) {
	return newTestAssetsCommon(t, true)
}

func newTestAssetsCommon(t *testing.T, metrics bool) (*assetManager, func()) {
	coreconfig.Reset()
	mdi := &databasemocks.Plugin{}
	mim := &identitymanagermocks.Manager{}
	mdm := &datamocks.Manager{}
	msa := &syncasyncmocks.Bridge{}
	mbm := &broadcastmocks.Manager{}
	mpm := &privatemessagingmocks.Manager{}
	mnm := &namespacemocks.Manager{}
	mti := &tokenmocks.Plugin{}
	mm := &metricsmocks.Manager{}
	mom := &operationmocks.Manager{}
	txHelper := txcommon.NewTransactionHelper(mdi, mdm)
	mm.On("IsMetricsEnabled").Return(metrics)
	mm.On("TransferSubmitted", mock.Anything)
	mom.On("RegisterHandler", mock.Anything, mock.Anything, mock.Anything)
	mti.On("Name").Return("ut").Maybe()
	ctx, cancel := context.WithCancel(context.Background())
	a, err := NewAssetManager(ctx, mim, mdm, msa, mbm, mpm, mm, mom, txHelper, mnm)
	assert.NoError(t, err)
	am := a.(*assetManager)
	am.txHelper = &txcommonmocks.Helper{}
	return am, cancel
}

func TestInitFail(t *testing.T) {
	_, err := NewAssetManager(context.Background(), nil, nil, nil, nil, nil, nil, nil, nil, nil)
	assert.Regexp(t, "FF10128", err)
}

func TestName(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()
	assert.Equal(t, "AssetManager", am.Name())
}

func TestGetTokenBalances(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	fb := database.TokenBalanceQueryFactory.NewFilter(context.Background())
	f := fb.And()
	mdi := &databasemocks.Plugin{}
	mdi.On("GetTokenBalances", context.Background(), f).Return([]*core.TokenBalance{}, nil, nil)
	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetDatabasePlugin", mock.Anything, mock.Anything).Return(mdi, nil)

	_, _, err := am.GetTokenBalances(context.Background(), "ns1", f)
	assert.NoError(t, err)
}

func TestGetTokenBalancesDBFail(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	fb := database.TokenBalanceQueryFactory.NewFilter(context.Background())
	f := fb.And()
	mdi := &databasemocks.Plugin{}
	mdi.On("GetTokenBalances", context.Background(), f).Return([]*core.TokenBalance{}, nil, nil)
	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetDatabasePlugin", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))

	_, _, err := am.GetTokenBalances(context.Background(), "ns1", f)
	assert.Regexp(t, "pop", err)
}

func TestSelectTokenPluginFail(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetTokensPlugins", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))

	_, err := am.selectTokenPlugin(context.Background(), "test", "ns1")
	assert.Regexp(t, "pop", err)
}

func TestGetTokenAccounts(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	fb := database.TokenBalanceQueryFactory.NewFilter(context.Background())
	f := fb.And()
	mdi := &databasemocks.Plugin{}
	mdi.On("GetTokenAccounts", context.Background(), f).Return([]*core.TokenAccount{}, nil, nil)
	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetDatabasePlugin", mock.Anything, mock.Anything).Return(mdi, nil)
	_, _, err := am.GetTokenAccounts(context.Background(), "ns1", f)
	assert.NoError(t, err)
}

func TestGetTokenAccountsDBFail(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	fb := database.TokenBalanceQueryFactory.NewFilter(context.Background())
	f := fb.And()
	mdi := &databasemocks.Plugin{}
	mdi.On("GetTokenAccounts", context.Background(), f).Return([]*core.TokenAccount{}, nil, nil)
	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetDatabasePlugin", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))
	_, _, err := am.GetTokenAccounts(context.Background(), "ns1", f)
	assert.Regexp(t, "pop", err)
}

func TestGetTokenAccountPools(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	fb := database.TokenBalanceQueryFactory.NewFilter(context.Background())
	f := fb.And()
	mdi := &databasemocks.Plugin{}
	mdi.On("GetTokenAccountPools", context.Background(), "0x1", f).Return([]*core.TokenAccountPool{}, nil, nil)
	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetDatabasePlugin", mock.Anything, mock.Anything).Return(mdi, nil)
	_, _, err := am.GetTokenAccountPools(context.Background(), "ns1", "0x1", f)
	assert.NoError(t, err)
}

func TestGetTokenAccountPoolsDBFail(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	fb := database.TokenBalanceQueryFactory.NewFilter(context.Background())
	f := fb.And()
	mdi := &databasemocks.Plugin{}
	mdi.On("GetTokenAccountPools", context.Background(), "0x1", f).Return([]*core.TokenAccountPool{}, nil, nil)
	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetDatabasePlugin", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))
	_, _, err := am.GetTokenAccountPools(context.Background(), "ns1", "0x1", f)
	assert.Regexp(t, "pop", err)
}

func TestGetTokenConnectors(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	mti := &tokenmocks.Plugin{}
	mti.On("Name").Return("ut").Maybe()
	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetTokensPlugins", mock.Anything, mock.Anything).Return(map[string]tokens.Plugin{"magic-tokens": mti}, nil)

	connectors, err := am.GetTokenConnectors(context.Background(), "ns1")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(connectors))
	assert.Equal(t, "magic-tokens", connectors[0].Name)
}

func TestGetTokenConnectorsFail(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetTokensPlugins", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))

	connectors, err := am.GetTokenConnectors(context.Background(), "ns1")
	assert.Regexp(t, "pop", err)
	assert.Nil(t, connectors)
}

func TestGetDefaultTokenConnectorsFail(t *testing.T) {
	am, cancel := newTestAssets(t)
	defer cancel()

	mnm := am.namespace.(*namespacemocks.Manager)
	mnm.On("GetTokensPlugins", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))

	connectors, err := am.GetTokenConnectors(context.Background(), "ns1")
	assert.Regexp(t, "pop", err)
	assert.Nil(t, connectors)
}
