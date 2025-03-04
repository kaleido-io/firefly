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
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
)

const (
	// PaladinClientConfigKey is a sub-key in the config to contain all the connection details for RPC client
	PaladinRPCClientConfigKey = "rpc"
)

func (p *Paladin) InitConfig(config config.Section) {
	rpcConf := config.SubSection(PaladinRPCClientConfigKey)
	// this inits ffresty too
	wsclient.InitConfig(rpcConf)
}
