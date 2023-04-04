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

package none

import (
	"context"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly/pkg/leaderelection"
)

// Rather than implementing the logic of "no leader election" everywhere throughout the code
// this plugin is used as the defacto behavior when no leader election plugin is defined.
// This means we can just implement this in one place, and the rest of the code always
// works the same way.
type None struct {
}

func (k *None) Name() string {
	return "none"
}

func (k *None) InitConfig(config config.Section) {}

func (k *None) Init(ctx context.Context, config config.Section) error {
	return nil
}

func (k *None) Capabilities() *leaderelection.Capabilities {
	return &leaderelection.Capabilities{}
}

func (k *None) RunLeaderElection(ctx context.Context, electionResult chan bool) {
	// Always become the leader immediately
	electionResult <- true
}
