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

package apiserver

import (
	"net/http"

	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/internal/oapispec"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
)

var getConfigRecord = &oapispec.Route{
	Name:   "getConfigRecord",
	Path:   "config/records/{key}",
	Method: http.MethodGet,
	PathParams: []*oapispec.PathParam{
		{Name: "key", Example: "database", Description: coremsgs.APIMessageTBD},
	},
	QueryParams:     nil,
	FilterFactory:   database.ConfigRecordQueryFactory,
	Description:     coremsgs.APIMessageTBD,
	JSONInputValue:  nil,
	JSONOutputValue: func() interface{} { return fftypes.JSONAnyPtr("{}") },
	JSONOutputCodes: []int{http.StatusOK},
	JSONHandler: func(r *oapispec.APIRequest) (output interface{}, err error) {
		configRecord, err := getOr(r.Ctx).GetConfigRecord(r.Ctx, r.PP["key"])
		return configRecord.Value, err
	},
}
