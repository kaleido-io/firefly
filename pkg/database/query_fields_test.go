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

package database

import (
	"testing"
	"time"

	"github.com/hyperledger/firefly/pkg/fftypes"
	"github.com/stretchr/testify/assert"
)

func TestNullField(t *testing.T) {

	f := nullField{}
	v, err := f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

	err = f.Scan("anything")
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

	assert.Equal(t, "null", f.String())
}

func TestStringField(t *testing.T) {

	f := stringField{}

	err := f.Scan("test")
	assert.NoError(t, err)
	v, err := f.Value()
	assert.NoError(t, err)
	assert.Equal(t, "test", v)

	err = f.Scan(nil)
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Equal(t, "", v)

}

func TestUUIDField(t *testing.T) {

	f := uuidField{}

	err := f.Scan("")
	assert.NoError(t, err)
	v, err := f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

	u1 := fftypes.NewUUID()
	err = f.Scan(u1.String())
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Equal(t, v, u1.String())

	err = f.Scan(nil)
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

}

func TestBytes32Field(t *testing.T) {

	f := bytes32Field{}

	err := f.Scan("")
	assert.NoError(t, err)
	v, err := f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

	b1 := fftypes.NewRandB32()
	err = f.Scan(b1.String())
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Equal(t, v, b1.String())

	err = f.Scan(nil)
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

}

func TestTimeField(t *testing.T) {

	f := timeField{}

	now := time.Now()
	err := f.Scan(now.Format(time.RFC3339Nano))
	assert.NoError(t, err)
	v, err := f.Value()
	assert.NoError(t, err)
	assert.Equal(t, v, now.UnixNano())

	err = f.Scan(nil)
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

}

func TestJSONField(t *testing.T) {

	f := jsonField{}

	err := f.Scan("{}")
	assert.NoError(t, err)
	v, err := f.Value()
	assert.NoError(t, err)
	assert.Equal(t, v, []byte("{}"))

	err = f.Scan(nil)
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.Nil(t, v)

}

func TestBoolField(t *testing.T) {

	f := boolField{}

	err := f.Scan("true")
	assert.NoError(t, err)
	v, err := f.Value()
	assert.NoError(t, err)
	assert.True(t, v.(bool))

	err = f.Scan(nil)
	assert.NoError(t, err)
	v, err = f.Value()
	assert.NoError(t, err)
	assert.False(t, v.(bool))

}