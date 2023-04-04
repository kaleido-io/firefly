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

package leaderelection

import (
	"context"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly/pkg/core"
)

// Plugin is the interface implemented by leaderelection interface
type Plugin interface {
	core.Named

	// InitConfig initializes the set of configuration options that are valid, with defaults. Called on all plugins.
	InitConfig(config config.Section)

	// Init initializes the plugin, with configuration
	Init(ctx context.Context, config config.Section) error

	// Capabilities returns capabilities - not called until after Init
	Capabilities() *Capabilities

	// Try to become the leader
	RunLeaderElection(ctx context.Context, electionResult chan bool)
}

type Capabilities struct {
}
