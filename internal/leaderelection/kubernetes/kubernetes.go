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

package kubernetes

import (
	"context"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly/pkg/leaderelection"
	kleaderelection "k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

type Kubernetes struct {
	electionResult chan bool
}

func (k *Kubernetes) Name() string {
	return "kubernetes"
}

func (k *Kubernetes) InitConfig(config config.Section) {}

func (k *Kubernetes) Init(ctx context.Context, name string, config config.Section) error {
	return nil
}

func (k *Kubernetes) Capabilities() *leaderelection.Capabilities {
	return &leaderelection.Capabilities{}
}

func (k *Kubernetes) RunLeaderElection(ctx context.Context, electionResult chan bool) {
	k.electionResult = electionResult
	go k.runLeaderElection(ctx, &resourcelock.LeaseLock{}, "id")
}

func (k *Kubernetes) runLeaderElection(ctx context.Context, lock *resourcelock.LeaseLock, id string) {
	kleaderelection.RunOrDie(ctx, kleaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: kleaderelection.LeaderCallbacks{
			OnStartedLeading: func(c context.Context) {
				// doStuff()
				k.electionResult <- true
			},
			OnStoppedLeading: func() {
				// klog.Info("no longer the leader, staying inactive.")
				k.electionResult <- false
			},
			OnNewLeader: func(current_id string) {
				if current_id == id {
					// klog.Info("still the leader!")
					return
				}
				// klog.Info("new leader is %s", current_id)
			},
		},
	})
}
