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

//go:build !reference
// +build !reference

package apiserver

import (
	"context"
	"crypto/sha1"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffapi"
	"github.com/hyperledger/firefly/internal/coreconfig"

	"github.com/stretchr/testify/assert"
)

func TestDiffSwaggerYAML(t *testing.T) {
	coreconfig.Reset()
	config.Set(coreconfig.APIOASPanicOnMissingDescription, true)
	as := &apiServer{}
	hf := as.handlerFactory()
	handler := &ffapi.OpenAPIHandlerFactory{
		BaseSwaggerGenOptions: as.baseSwaggerGenOptions(),
		StaticPublicURL:       "http://localhost:5000",
	}
	s := httptest.NewServer(http.HandlerFunc(hf.APIWrapper(handler.OpenAPIHandler("/api/v1", ffapi.OpenAPIFormatYAML, routes))))
	defer s.Close()

	res, err := http.Get(s.URL)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	b, _ := ioutil.ReadAll(res.Body)
	doc, err := openapi3.NewLoader().LoadFromData(b)
	assert.NoError(t, err)
	err = doc.Validate(context.Background())
	assert.NoError(t, err)

	actualSwaggerHash := sha1.New()
	actualSwaggerHash.Write(b)

	var existingSwaggerBytes []byte
	existingSwaggerBytes, err = os.ReadFile(filepath.Join("..", "..", "docs", "swagger", "swagger.yaml"))
	assert.NoError(t, err)

	expectedSwaggerHash := sha1.New()
	expectedSwaggerHash.Write(existingSwaggerBytes)

	assert.Equal(t, actualSwaggerHash.Sum(nil), expectedSwaggerHash.Sum(nil), "The swagger generated by the code did not match the swagger.yml file in git. Did you forget to run `make reference`?")
}
