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
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
)

const (
	// PaladinClientConfigKey is a sub-key in the config to contain all the connection details for RPC client
	PaladinRPCClientConfigKey = "rpc"

	// AddressResolverConfigKey is a sub-key in the config to contain an address resolver config.
	AddressResolverConfigKey = "addressResolver"
	// AddressResolverEnable whether a config defined address resolver should be used instead of making resolve calls to the RPC endpoint
	AddressResolverEnable = "addressResolver"
	// AddressResolverAlwaysResolve causes the address resolve to be invoked on every API call that resolves an address, regardless of whether the input conforms to an 0x address, and disables any caching
	AddressResolverAlwaysResolve = "alwaysResolve"
	// AddressResolverMethod the HTTP method to use to call the address resolver (default GET)
	AddressResolverMethod = "method"
	// AddressResolverURLTemplate the URL go template string to use when calling the address resolver - a ".intent" string can be used in the go template
	AddressResolverURLTemplate = "urlTemplate"
	// AddressResolverBodyTemplate the body go template string to use when calling the address resolver - a ".intent" string can be used in the go template
	AddressResolverBodyTemplate = "bodyTemplate"
	// AddressResolverResponseField the name of a JSON field that is provided in the response, that contains the ethereum address (default "address")
	AddressResolverResponseField = "responseField"
)

func (p *Paladin) InitConfig(config config.Section) {
	rpcConf := config.SubSection(PaladinRPCClientConfigKey)
	// this inits ffresty too
	wsclient.InitConfig(rpcConf)

	addressResolverConf := config.SubSection(AddressResolverConfigKey)
	ffresty.InitConfig(addressResolverConf)
	addressResolverConf.AddKnownKey(AddressResolverEnable, false)
	addressResolverConf.AddKnownKey(AddressResolverAlwaysResolve)
	addressResolverConf.AddKnownKey(AddressResolverMethod)
	addressResolverConf.AddKnownKey(AddressResolverURLTemplate)
	addressResolverConf.AddKnownKey(AddressResolverBodyTemplate)
	addressResolverConf.AddKnownKey(AddressResolverResponseField)
}
