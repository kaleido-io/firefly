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

package definitions

import (
	"context"

	"github.com/hyperledger/firefly/internal/log"
	"github.com/hyperledger/firefly/pkg/fftypes"
)

func (sh *definitionHandlers) persistContractDefinition(ctx context.Context, cd *fftypes.ContractDefinitionBroadcast) (valid bool, err error) {
	err = sh.database.InsertContractDefinition(ctx, &cd.ContractDefinition)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (sh *definitionHandlers) handleContractDefinitionBroadcast(ctx context.Context, msg *fftypes.Message, data []*fftypes.Data) (valid bool, err error) {
	l := log.L(ctx)
	var broadcast fftypes.ContractDefinitionBroadcast
	valid = sh.getSystemBroadcastPayload(ctx, msg, data, &broadcast)
	if valid {
		if err = broadcast.Validate(ctx, true); err != nil {
			l.Warnf("Unable to process contract definition broadcast %s - validate failed: %s", msg.Header.ID, err)
			valid = false
		} else {
			broadcast.Message = msg.Header.ID
			valid, err = sh.persistContractDefinition(ctx, &broadcast)
			if err != nil {
				return valid, err
			}
		}
	}

	var event *fftypes.Event
	if valid {
		l.Infof("Contract definition created id=%s author=%s", broadcast.ID, msg.Header.Author)
		event = fftypes.NewEvent(fftypes.EventTypePoolConfirmed, broadcast.Namespace, broadcast.ID)
	} else {
		l.Warnf("Contract definition rejected id=%s author=%s", broadcast.ID, msg.Header.Author)
		event = fftypes.NewEvent(fftypes.EventTypePoolRejected, broadcast.Namespace, broadcast.ID)
	}
	err = sh.database.InsertEvent(ctx, event)
	return valid, err
}
