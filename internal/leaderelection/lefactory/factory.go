// Copyright © 2023 Kaleido, Inc.
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

package lefactory

import (
	"context"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/internal/leaderelection/kubernetes"
	"github.com/hyperledger/firefly/internal/leaderelection/none"
	"github.com/hyperledger/firefly/pkg/leaderelection"
)

var (
	NewKubernetesPluginName = (*kubernetes.Kubernetes)(nil).Name()
	NewNonePluginName       = (*none.None)(nil).Name()
)

var pluginsByName = map[string]func() leaderelection.Plugin{
	NewKubernetesPluginName: func() leaderelection.Plugin { return &kubernetes.Kubernetes{} },
	NewNonePluginName:       func() leaderelection.Plugin { return &none.None{} },
}

func InitConfig(config config.ArraySection) {
	config.AddKnownKey(coreconfig.PluginConfigName)
	config.AddKnownKey(coreconfig.PluginConfigType)
	for name, plugin := range pluginsByName {
		plugin().InitConfig(config.SubSection(name))
	}
}

func GetPlugin(ctx context.Context, pluginName string) (leaderelection.Plugin, error) {
	plugin, ok := pluginsByName[pluginName]
	if !ok {
		return nil, i18n.NewError(ctx, coremsgs.MsgUnknownBlockchainPlugin, pluginName)
	}
	return plugin(), nil
}
