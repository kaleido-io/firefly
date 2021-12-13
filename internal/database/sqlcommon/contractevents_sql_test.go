// Copyright © 2021 Kaleido, Inc.
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

package sqlcommon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
	"github.com/stretchr/testify/assert"
)

func TestContractEventsE2EWithDB(t *testing.T) {
	s, cleanup := newSQLiteTestProvider(t)
	defer cleanup()
	ctx := context.Background()

	// Create a new contract event entry
	event := &fftypes.ContractEvent{
		ID:           fftypes.NewUUID(),
		Namespace:    "ns",
		Subscription: fftypes.NewUUID(),
		Name:         "Changed",
		Outputs:      fftypes.JSONObject{"value": 1},
		Info:         fftypes.JSONObject{"blockNumber": 1},
	}

	err := s.InsertContractEvent(ctx, event)
	assert.NotNil(t, event.Created)
	assert.NoError(t, err)
	eventJson, _ := json.Marshal(&event)

	// Query back the event (by query filter)
	fb := database.ContractEventQueryFactory.NewFilter(ctx)
	filter := fb.And(
		fb.Eq("name", "Changed"),
		fb.Eq("subscriptionid", event.Subscription),
	)
	events, res, err := s.GetContractEvents(ctx, filter.Count(true))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, int64(1), *res.TotalCount)
	eventReadJson, _ := json.Marshal(events[0])
	assert.Equal(t, string(eventJson), string(eventReadJson))

	// Query back the event (by ID)
	eventRead, err := s.GetContractEventByID(ctx, event.ID)
	assert.NoError(t, err)
	eventReadJson, _ = json.Marshal(eventRead)
	assert.Equal(t, string(eventJson), string(eventReadJson))
}
