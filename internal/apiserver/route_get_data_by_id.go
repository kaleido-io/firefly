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
	"github.com/hyperledger/firefly/pkg/core"
)

var getDataByID = &oapispec.Route{
	Name:   "getDataByID",
	Path:   "data/{dataid}",
	Method: http.MethodGet,
	PathParams: []*oapispec.PathParam{
		{Name: "dataid", Description: coremsgs.APIParamsDataID},
	},
	QueryParams:     nil,
	FilterFactory:   nil,
	DescriptionKey:  coremsgs.APIEndpointsGetDataByID,
	JSONInputValue:  nil,
	JSONOutputValue: func() interface{} { return &core.Data{} },
	JSONOutputCodes: []int{http.StatusOK},
	JSONHandler: func(r *oapispec.APIRequest) (output interface{}, err error) {
		output, err = getOr(r.Ctx).GetDataByID(r.Ctx, extractNamespace(r.PP), r.PP["dataid"])
		return output, err
	},
}
