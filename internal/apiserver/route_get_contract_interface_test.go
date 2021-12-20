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

package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/firefly/mocks/contractmocks"
	"github.com/hyperledger/firefly/pkg/fftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetContractInterface(t *testing.T) {
	o, r := newTestAPIServer()
	mcm := &contractmocks.Manager{}
	o.On("Contracts").Return(mcm)
	input := fftypes.Datatype{}
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(&input)
	req := httptest.NewRequest("GET", "/api/v1/namespaces/ns1/contracts/interfaces/62757af9-b539-4b77-adfa-c0e7beebbfd3", &buf)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res := httptest.NewRecorder()

	mcm.On("GetFFIByID", mock.Anything, "62757af9-b539-4b77-adfa-c0e7beebbfd3").
		Return(&fftypes.FFI{}, nil)
	r.ServeHTTP(res, req)

	assert.Equal(t, 200, res.Result().StatusCode)
}

func TestGetContractInterfaceWithChildren(t *testing.T) {
	o, r := newTestAPIServer()
	mcm := &contractmocks.Manager{}
	o.On("Contracts").Return(mcm)
	input := fftypes.Datatype{}
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(&input)
	req := httptest.NewRequest("GET", "/api/v1/namespaces/ns1/contracts/interfaces/62757af9-b539-4b77-adfa-c0e7beebbfd3?fetchchildren", &buf)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res := httptest.NewRecorder()

	mcm.On("GetFFIByIDWithChildren", mock.Anything, "62757af9-b539-4b77-adfa-c0e7beebbfd3").
		Return(&fftypes.FFI{}, nil)
	r.ServeHTTP(res, req)

	assert.Equal(t, 200, res.Result().StatusCode)
}