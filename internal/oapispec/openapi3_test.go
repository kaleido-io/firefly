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

package oapispec

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
	"github.com/stretchr/testify/assert"
)

var testRoutes = []*Route{
	{
		Name:   "op1",
		Path:   "namespaces/{ns}/example1/{id}",
		Method: http.MethodPost,
		PathParams: []*PathParam{
			{Name: "ns", ExampleFromConf: coreconfig.NamespacesDefault, Description: coremsgs.APIMessageTBD},
			{Name: "id", Description: coremsgs.APIMessageTBD},
		},
		QueryParams:     nil,
		FilterFactory:   nil,
		Description:     coremsgs.APIMessageTBD,
		JSONInputValue:  func() interface{} { return &fftypes.MessageInOut{} },
		JSONInputMask:   nil,
		JSONOutputValue: func() interface{} { return &fftypes.Batch{} },
		JSONOutputCodes: []int{http.StatusOK},
	},
	{
		Name:           "op2",
		Path:           "example2",
		Method:         http.MethodGet,
		PathParams:     nil,
		QueryParams:    nil,
		FilterFactory:  database.MessageQueryFactory,
		Description:    coremsgs.APIMessageTBD,
		JSONInputValue: func() interface{} { return nil },
		JSONInputSchema: func(ctx context.Context) string {
			return `{
			"type": "object",
			"properties": {
				"id": {
					"type": "string"
				}
			}
		}`
		},
		JSONOutputSchema: func(ctx context.Context) string {
			return `{
			"type": "object",
			"properties": {
				"id": {
					"type": "string"
				}
			}
		}`
		},
		JSONOutputCodes: []int{http.StatusOK},
	},
	{
		Name:       "op3",
		Path:       "example2",
		Method:     http.MethodPut,
		PathParams: nil,
		QueryParams: []*QueryParam{
			{Name: "ns", ExampleFromConf: coreconfig.NamespacesDefault, Description: coremsgs.APIMessageTBD},
			{Name: "id", Description: coremsgs.APIMessageTBD},
			{Name: "myfield", Default: "val1", Description: coremsgs.APIMessageTBD},
		},
		FilterFactory:   nil,
		Description:     coremsgs.APIMessageTBD,
		JSONInputValue:  func() interface{} { return &fftypes.MessageInOut{} },
		JSONOutputValue: func() interface{} { return nil },
		JSONOutputCodes: []int{http.StatusNoContent},
		FormParams: []*FormParam{
			{Name: "metadata", Description: coremsgs.APIMessageTBD},
		},
		FormUploadHandler: func(r *APIRequest) (output interface{}, err error) { return nil, nil },
	},
	{
		Name:   "op4",
		Path:   "example2/{id}",
		Method: http.MethodDelete,
		PathParams: []*PathParam{
			{Name: "id", Description: coremsgs.APIMessageTBD},
		},
		QueryParams:     nil,
		FilterFactory:   nil,
		Description:     coremsgs.APIMessageTBD,
		JSONInputValue:  func() interface{} { return nil },
		JSONOutputValue: func() interface{} { return nil },
		JSONOutputCodes: []int{http.StatusNoContent},
	},
	{
		Name:            "op5",
		Path:            "example2",
		Method:          http.MethodPost,
		PathParams:      nil,
		QueryParams:     nil,
		FilterFactory:   nil,
		Description:     coremsgs.APIMessageTBD,
		JSONInputValue:  func() interface{} { return &fftypes.Data{} },
		JSONInputMask:   []string{"id"},
		JSONOutputValue: func() interface{} { return &fftypes.Data{} },
		JSONOutputCodes: []int{http.StatusOK},
	},
}

func TestOpenAPI3SwaggerGen(t *testing.T) {
	coreconfig.Reset()

	doc := SwaggerGen(context.Background(), testRoutes, &SwaggerGenConfig{
		Title:   "UnitTest",
		Version: "1.0",
		BaseURL: "http://localhost:12345/api/v1",
	})
	err := doc.Validate(context.Background())
	assert.NoError(t, err)

	b, err := yaml.Marshal(doc)
	assert.NoError(t, err)
	fmt.Print(string(b))
}

func TestDuplicateOperationIDCheck(t *testing.T) {
	routes := []*Route{
		{Name: "op1"}, {Name: "op1"},
	}
	assert.PanicsWithValue(t, "Duplicate/invalid name (used as operation ID in swagger): op1", func() {
		_ = SwaggerGen(context.Background(), routes, &SwaggerGenConfig{
			Title:   "UnitTest",
			Version: "1.0",
			BaseURL: "http://localhost:12345/api/v1",
		})
	})
}

func TestBadCustomSchema(t *testing.T) {

	coreconfig.Reset()
	routes := []*Route{
		{
			Name:            "op1",
			Path:            "namespaces/{ns}/example1/{id}",
			Method:          http.MethodPost,
			JSONInputValue:  func() interface{} { return &fftypes.Message{} },
			JSONInputMask:   []string{"id"},
			JSONOutputCodes: []int{http.StatusOK},
			JSONInputSchema: func(ctx context.Context) string { return `!json` },
		},
	}
	assert.PanicsWithValue(t, "invalid schema for *fftypes.Message: invalid character '!' looking for beginning of value", func() {
		_ = SwaggerGen(context.Background(), routes, &SwaggerGenConfig{
			Title:   "UnitTest",
			Version: "1.0",
			BaseURL: "http://localhost:12345/api/v1",
		})
	})
}

func TestWildcards(t *testing.T) {

	coreconfig.Reset()
	routes := []*Route{
		{
			Name:            "op1",
			Path:            "namespaces/{ns}/example1/{id:.*wildcard.*}",
			Method:          http.MethodPost,
			JSONInputValue:  func() interface{} { return &fftypes.Message{} },
			JSONInputMask:   []string{"id"},
			JSONOutputCodes: []int{http.StatusOK},
		},
	}
	swagger := SwaggerGen(context.Background(), routes, &SwaggerGenConfig{
		Title:   "UnitTest",
		Version: "1.0",
		BaseURL: "http://localhost:12345/api/v1",
	})
	assert.NotNil(t, swagger.Paths["/namespaces/{ns}/example1/{id}"])
}
