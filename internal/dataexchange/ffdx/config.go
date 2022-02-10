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

package ffdx

import (
	"github.com/hyperledger/firefly/internal/config"
	"github.com/hyperledger/firefly/internal/config/wsconfig"
)

const (
	// DataExchangeManifestEnabled determines whether to require+validate a manifest from other DX instances in the network. Must be supported by the connector
	DataExchangeManifestEnabled = "manifestEnabled"
	// DataExchangeReInitEnabled instructs FireFly to always post all current nodes to the /init API before connecting or reconnecting to the connector
	DataExchangeReInitEnabled = "reInitEnabled"
)

func (h *FFDX) InitPrefix(prefix config.Prefix) {
	wsconfig.InitPrefix(prefix)
	prefix.AddKnownKey(DataExchangeManifestEnabled, false)
	prefix.AddKnownKey(DataExchangeReInitEnabled, false)
}
