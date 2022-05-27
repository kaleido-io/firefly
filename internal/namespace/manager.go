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

package namespace

import (
	"context"
	"fmt"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/pkg/blockchain"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/dataexchange"
	"github.com/hyperledger/firefly/pkg/sharedstorage"
	"github.com/hyperledger/firefly/pkg/tokens"
)

type Manager interface {
	// Init initializes the manager
	Init(ctx context.Context, di database.Plugin, bc map[string]blockchain.Plugin, db map[string]database.Plugin, dx map[string]dataexchange.Plugin, ss map[string]sharedstorage.Plugin, tokens map[string]tokens.Plugin) error
	GetDatabasePlugin(ctx context.Context, namespace string) (database.Plugin, error)
	GetTokensPlugins(ctx context.Context, namespace string) (map[string]tokens.Plugin, error)
}

type namespace struct {
	database      database.Plugin
	blockchain    blockchain.Plugin
	dataexchange  dataexchange.Plugin
	sharedstorage sharedstorage.Plugin
	tokens        map[string]tokens.Plugin
}

type plugins struct {
	blockchains    map[string]blockchain.Plugin
	databases      map[string]database.Plugin
	dataexchanges  map[string]dataexchange.Plugin
	sharedstorages map[string]sharedstorage.Plugin
	tokens         map[string]tokens.Plugin
}

type namespaceManager struct {
	ctx        context.Context
	nsConfig   map[string]config.Section
	namespaces map[string]namespace
}

func NewNamespaceManager(ctx context.Context) Manager {
	nm := &namespaceManager{
		ctx:        ctx,
		nsConfig:   buildNamespaceMap(ctx),
		namespaces: map[string]namespace{},
	}
	return nm
}

func (nm *namespaceManager) GetDatabasePlugin(ctx context.Context, namespace string) (database.Plugin, error) {
	ns, ok := nm.namespaces[namespace]
	if !ok {
		// return nil, i18n.NewError(nm.ctx)
	}

	fmt.Printf("%+v\n", ns)

	if ns.database != nil {
		return ns.database, nil
	}

	return nil, fmt.Errorf("bad db")
}

func (nm *namespaceManager) GetTokensPlugins(ctx context.Context, namespace string) (map[string]tokens.Plugin, error) {
	ns, ok := nm.namespaces[namespace]
	if !ok {
		return nil, fmt.Errorf("cant find ns")
	}

	if ns.tokens != nil {
		return ns.tokens, nil
	}

	return nil, fmt.Errorf("bad tokens")
}

func buildNamespaceMap(ctx context.Context) map[string]config.Section {
	conf := namespacePredefined
	namespaces := make(map[string]config.Section, conf.ArraySize())
	for i := 0; i < conf.ArraySize(); i++ {
		nsConfig := conf.ArrayEntry(i)
		name := nsConfig.GetString(coreconfig.NamespaceName)
		if name != "" {
			if _, ok := namespaces[name]; ok {
				log.L(ctx).Warnf("Duplicate predefined namespace (ignored): %s", name)
			}
			namespaces[name] = nsConfig
		}
	}
	return namespaces
}

func (nm *namespaceManager) Init(ctx context.Context, di database.Plugin, bc map[string]blockchain.Plugin, db map[string]database.Plugin, dx map[string]dataexchange.Plugin, ss map[string]sharedstorage.Plugin, tokens map[string]tokens.Plugin) error {
	plugins := &plugins{
		blockchains:    bc,
		databases:      db,
		dataexchanges:  dx,
		sharedstorages: ss,
		tokens:         tokens,
	}
	return nm.initNamespaces(ctx, di, plugins)
}

func (nm *namespaceManager) getPredefinedNamespaces(ctx context.Context, plugins *plugins) ([]*core.Namespace, error) {
	defaultNS := config.GetString(coreconfig.NamespacesDefault)
	namespaces := []*core.Namespace{
		{
			Name:        core.SystemNamespace,
			Type:        core.NamespaceTypeSystem,
			Description: i18n.Expand(ctx, coremsgs.CoreSystemNSDescription),
		},
	}
	i := 0
	foundDefault := false
	for name, nsObject := range nm.nsConfig {
		if err := nm.validateNamespaceConfig(ctx, name, i, nsObject, plugins); err != nil {
			return nil, err
		}
		i++
		foundDefault = foundDefault || name == defaultNS
		namespaces = append(namespaces, &core.Namespace{
			Type:        core.NamespaceTypeLocal,
			Name:        name,
			Description: nsObject.GetString("description"),
		})
	}
	if !foundDefault {
		return nil, i18n.NewError(ctx, coremsgs.MsgDefaultNamespaceNotFound, defaultNS)
	}
	return namespaces, nil
}

func (nm *namespaceManager) initNamespaces(ctx context.Context, di database.Plugin, plugins *plugins) error {
	predefined, err := nm.getPredefinedNamespaces(ctx, plugins)
	if err != nil {
		return err
	}
	for _, newNS := range predefined {
		ns, err := di.GetNamespace(ctx, newNS.Name)
		if err != nil {
			return err
		}
		var updated bool
		if ns == nil {
			updated = true
			newNS.ID = fftypes.NewUUID()
			newNS.Created = fftypes.Now()
		} else {
			// Only update if the description has changed, and the one in our DB is locally defined
			updated = ns.Description != newNS.Description && ns.Type == core.NamespaceTypeLocal
		}
		if updated {
			if err := di.UpsertNamespace(ctx, newNS, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (nm *namespaceManager) validateNamespaceConfig(ctx context.Context, name string, index int, conf config.Section, plugins *plugins) error {
	if err := core.ValidateFFNameField(ctx, name, fmt.Sprintf("namespaces.predefined[%d].name", index)); err != nil {
		return err
	}

	if name == core.SystemNamespace || conf.GetString(coreconfig.NamespaceRemoteName) == core.SystemNamespace {
		return i18n.NewError(ctx, coremsgs.MsgFFSystemReservedName, core.SystemNamespace)
	}

	mode := conf.GetString(coreconfig.NamespaceMode)
	pluginNames := conf.GetStringSlice(coreconfig.NamespacePlugins)

	// If no plugins are found when querying the config, assume older config file
	if len(pluginNames) == 0 {
		for name := range plugins.blockchains {
			pluginNames = append(pluginNames, name)
		}

		for name := range plugins.dataexchanges {
			pluginNames = append(pluginNames, name)
		}

		for name := range plugins.sharedstorages {
			pluginNames = append(pluginNames, name)
		}

		for name := range plugins.databases {
			pluginNames = append(pluginNames, name)
		}

		for name := range plugins.tokens {
			pluginNames = append(pluginNames, name)
		}
	}

	switch mode {
	// Multiparty is the default mode when none is provided
	case "multiparty":
		if err := nm.validateMultiPartyConfig(ctx, name, pluginNames, plugins); err != nil {
			return err
		}
	case "gateway":
		if err := nm.validateGatewayConfig(ctx, name, pluginNames, plugins); err != nil {
			return err
		}
	default:
		return i18n.NewError(ctx, coremsgs.MsgInvalidNamespaceMode, name)
	}
	return nil
}

func (nm *namespaceManager) validateMultiPartyConfig(ctx context.Context, name string, pluginNames []string, pluginInstances *plugins) error {
	var dbPlugin bool
	var ssPlugin bool
	var dxPlugin bool
	var bcPlugin bool

	ns := namespace{
		tokens: make(map[string]tokens.Plugin),
	}

	for _, pluginName := range pluginNames {
		if instance, ok := pluginInstances.blockchains[pluginName]; ok {
			if bcPlugin {
				return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayMultiplePluginType, name, "blockchain")
			}
			bcPlugin = true
			ns.blockchain = instance
			continue
		}
		if instance, ok := pluginInstances.dataexchanges[pluginName]; ok {
			if dxPlugin {
				return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayMultiplePluginType, name, "dataexchange")
			}
			dxPlugin = true
			ns.dataexchange = instance
			continue
		}
		if instance, ok := pluginInstances.sharedstorages[pluginName]; ok {
			if ssPlugin {
				return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayMultiplePluginType, name, "sharedstorage")
			}
			ssPlugin = true
			ns.sharedstorage = instance
			continue
		}
		if instance, ok := pluginInstances.databases[pluginName]; ok {
			if dbPlugin {
				return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayMultiplePluginType, name, "database")
			}
			dbPlugin = true
			ns.database = instance
			continue
		}
		if instance, ok := pluginInstances.tokens[pluginName]; ok {
			ns.tokens[pluginName] = instance
			continue
		}

		return i18n.NewError(ctx, coremsgs.MsgNamespaceUnknownPlugin, name, pluginName)
	}

	if !dbPlugin || !ssPlugin || !dxPlugin || !bcPlugin {
		return i18n.NewError(ctx, coremsgs.MsgNamespaceMultipartyConfiguration, name)
	}
	nm.namespaces[name] = ns

	return nil
}

func (nm *namespaceManager) validateGatewayConfig(ctx context.Context, name string, pluginNames []string, pluginInstances *plugins) error {
	var dbPlugin bool
	var bcPlugin bool

	ns := namespace{
		tokens: make(map[string]tokens.Plugin),
	}

	for _, pluginName := range pluginNames {
		if instance, ok := pluginInstances.blockchains[pluginName]; ok {
			if bcPlugin {
				return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayMultiplePluginType, name, "blockchain")
			}
			bcPlugin = true
			ns.blockchain = instance
			continue
		}
		if _, ok := pluginInstances.dataexchanges[pluginName]; ok {
			return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayInvalidPlugins, name)
		}
		if _, ok := pluginInstances.sharedstorages[pluginName]; ok {
			return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayInvalidPlugins, name)
		}
		if instance, ok := pluginInstances.databases[pluginName]; ok {
			if dbPlugin {
				return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayMultiplePluginType, name, "database")
			}
			dbPlugin = true
			ns.database = instance
			continue
		}
		if instance, ok := pluginInstances.tokens[pluginName]; ok {
			ns.tokens[pluginName] = instance
			continue
		}

		return i18n.NewError(ctx, coremsgs.MsgNamespaceUnknownPlugin, name, pluginName)
	}

	if !dbPlugin {
		return i18n.NewError(ctx, coremsgs.MsgNamespaceGatewayNoDB, name)
	}
	nm.namespaces[name] = ns

	return nil
}
