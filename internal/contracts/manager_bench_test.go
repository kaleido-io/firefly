// Copyright © 2026 Kaleido, Inc.
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

package contracts

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger-firefly/common/pkg/fftypes"
	"github.com/hyperledger-firefly/firefly/mocks/databasemocks"
	"github.com/hyperledger-firefly/firefly/pkg/core"
	"github.com/stretchr/testify/mock"
)

// BenchmarkContractAPILookup reproduces the load pattern from the bug report - many concurrent
// requests resolving the same contract API by name - and compares looking it up straight from
// the database on every call against looking it up through the new read-through cache.
// dbLatency stands in for the DB round trip (query + network I/O) the issue calls out.
func BenchmarkContractAPILookup(b *testing.B) {
	const apiName = "banana"
	const dbLatency = 500 * time.Microsecond

	api := &core.ContractAPI{
		Namespace: "ns1",
		Name:      apiName,
		Interface: &fftypes.FFIReference{ID: fftypes.NewUUID()},
	}

	b.Run("without_cache", func(b *testing.B) {
		cm := newTestContractManager()
		mdb := cm.database.(*databasemocks.Plugin)
		mdb.On("GetContractAPIByName", mock.Anything, "ns1", apiName).
			Run(func(mock.Arguments) { time.Sleep(dbLatency) }).
			Return(api, nil)

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cm.database.GetContractAPIByName(context.Background(), "ns1", apiName)
			}
		})
	})

	b.Run("with_cache", func(b *testing.B) {
		cm := newTestContractManager()
		mdb := cm.database.(*databasemocks.Plugin)
		mdb.On("GetContractAPIByName", mock.Anything, "ns1", apiName).
			Run(func(mock.Arguments) { time.Sleep(dbLatency) }).
			Return(api, nil).Once()

		// Prime the cache, exactly like the first request in a burst would.
		if _, err := cm.getContractAPIByName(context.Background(), apiName); err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cm.getContractAPIByName(context.Background(), apiName)
			}
		})
	})
}
