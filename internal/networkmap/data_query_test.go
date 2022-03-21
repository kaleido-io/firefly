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

package networkmap

import (
	"fmt"
	"testing"

	"github.com/hyperledger/firefly/mocks/databasemocks"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetOrganizationByNameOrIDOk(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).
		Return(&fftypes.Identity{IdentityBase: fftypes.IdentityBase{ID: id, Type: fftypes.IdentityTypeOrg}}, nil)
	res, err := nm.GetOrganizationByNameOrID(nm.ctx, id.String())
	assert.NoError(t, err)
	assert.Equal(t, *id, *res.ID)
}

func TestGetOrganizationByNameOrIDNotOrg(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).
		Return(&fftypes.Identity{IdentityBase: fftypes.IdentityBase{ID: id, Type: fftypes.IdentityTypeNode}}, nil)
	res, err := nm.GetOrganizationByNameOrID(nm.ctx, id.String())
	assert.NoError(t, err)
	assert.Nil(t, res)
}

func TestGetOrganizationByNameOrIDNotFound(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).Return(nil, nil)
	_, err := nm.GetOrganizationByNameOrID(nm.ctx, id.String())
	assert.Regexp(t, "FF10109", err)
}

func TestGetOrganizationByNameOrIDError(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).Return(nil, fmt.Errorf("pop"))
	_, err := nm.GetOrganizationByNameOrID(nm.ctx, id.String())
	assert.Regexp(t, "pop", err)
}

func TestGetOrganizationByNameBadName(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	_, err := nm.GetOrganizationByNameOrID(nm.ctx, "!bad")
	assert.Regexp(t, "FF10131", err)
}

func TestGetOrganizationByNameError(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByName", nm.ctx, fftypes.IdentityTypeOrg, fftypes.SystemNamespace, "bad").Return(nil, fmt.Errorf("pop"))
	_, err := nm.GetOrganizationByNameOrID(nm.ctx, "bad")
	assert.Regexp(t, "pop", err)
}

func TestGetNodeByNameOrIDOk(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).
		Return(&fftypes.Identity{IdentityBase: fftypes.IdentityBase{ID: id, Type: fftypes.IdentityTypeNode}}, nil)
	res, err := nm.GetNodeByNameOrID(nm.ctx, id.String())
	assert.NoError(t, err)
	assert.Equal(t, *id, *res.ID)
}

func TestGetNodeByNameOrIDWrongType(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).
		Return(&fftypes.Identity{IdentityBase: fftypes.IdentityBase{ID: id, Type: fftypes.IdentityTypeOrg}}, nil)
	res, err := nm.GetNodeByNameOrID(nm.ctx, id.String())
	assert.NoError(t, err)
	assert.Nil(t, res)
}

func TestGetNodeByNameOrIDNotFound(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).Return(nil, nil)
	_, err := nm.GetNodeByNameOrID(nm.ctx, id.String())
	assert.Regexp(t, "FF10109", err)
}

func TestGetNodeByNameOrIDError(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).Return(nil, fmt.Errorf("pop"))
	_, err := nm.GetNodeByNameOrID(nm.ctx, id.String())
	assert.Regexp(t, "pop", err)
}

func TestGetNodeByNameBadName(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	_, err := nm.GetNodeByNameOrID(nm.ctx, "!bad")
	assert.Regexp(t, "FF10131", err)
}

func TestGetNodeByNameError(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByName", nm.ctx, fftypes.IdentityTypeNode, fftypes.SystemNamespace, "bad").Return(nil, fmt.Errorf("pop"))
	_, err := nm.GetNodeByNameOrID(nm.ctx, "bad")
	assert.Regexp(t, "pop", err)
}

func TestGetOrganizations(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentities", nm.ctx, mock.Anything).Return([]*fftypes.Identity{}, nil, nil)
	res, _, err := nm.GetOrganizations(nm.ctx, database.IdentityQueryFactory.NewFilter(nm.ctx).And())
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestGetNodes(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentities", nm.ctx, mock.Anything).Return([]*fftypes.Identity{}, nil, nil)
	res, _, err := nm.GetNodes(nm.ctx, database.IdentityQueryFactory.NewFilter(nm.ctx).And())
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestGetIdentityByIDOk(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).
		Return(&fftypes.Identity{IdentityBase: fftypes.IdentityBase{ID: id, Type: fftypes.IdentityTypeOrg, Namespace: "ns1"}}, nil)
	res, err := nm.GetIdentityByID(nm.ctx, "ns1", id.String())
	assert.NoError(t, err)
	assert.Equal(t, *id, *res.ID)
}

func TestGetIdentityByIDNotFound(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).Return(nil, nil)
	_, err := nm.GetIdentityByID(nm.ctx, "ns1", id.String())
	assert.Regexp(t, "FF10109", err)
}

func TestGetIdentityByIDError(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).Return(nil, fmt.Errorf("pop"))
	_, err := nm.GetIdentityByID(nm.ctx, "ns1", id.String())
	assert.Regexp(t, "pop", err)
}

func TestGetIdentityByIDBadNS(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).
		Return(&fftypes.Identity{IdentityBase: fftypes.IdentityBase{ID: id, Type: fftypes.IdentityTypeOrg, Namespace: "ns1"}}, nil)
	_, err := nm.GetIdentityByID(nm.ctx, "ns2", id.String())
	assert.Regexp(t, "FF10109", err)
}

func TestGetIdentityByIDBadUUID(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	_, err := nm.GetIdentityByID(nm.ctx, "ns1", "bad")
	assert.Regexp(t, "FF10142", err)
}

func TestGetIdentities(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentities", nm.ctx, mock.Anything).Return([]*fftypes.Identity{}, nil, nil)
	res, _, err := nm.GetIdentities(nm.ctx, "ns1", database.IdentityQueryFactory.NewFilter(nm.ctx).And())
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestGetIdentityVerifiers(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).
		Return(&fftypes.Identity{IdentityBase: fftypes.IdentityBase{ID: id, Type: fftypes.IdentityTypeOrg, Namespace: "ns1"}}, nil)
	nm.database.(*databasemocks.Plugin).On("GetVerifiers", nm.ctx, mock.Anything).Return([]*fftypes.Verifier{}, nil, nil)
	res, _, err := nm.GetIdentityVerifiers(nm.ctx, "ns1", id.String(), database.IdentityQueryFactory.NewFilter(nm.ctx).And())
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestGetIdentityVerifiersIdentityFail(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	id := fftypes.NewUUID()
	nm.database.(*databasemocks.Plugin).On("GetIdentityByID", nm.ctx, id).Return(nil, fmt.Errorf("pop"))
	res, _, err := nm.GetIdentityVerifiers(nm.ctx, "ns1", id.String(), database.IdentityQueryFactory.NewFilter(nm.ctx).And())
	assert.Regexp(t, "pop", err)
	assert.Empty(t, res)
}

func TestGetVerifiers(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetVerifiers", nm.ctx, mock.Anything).Return([]*fftypes.Verifier{}, nil, nil)
	res, _, err := nm.GetVerifiers(nm.ctx, "ns1", database.VerifierQueryFactory.NewFilter(nm.ctx).And())
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestGetVerifierByHashOk(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	hash := fftypes.NewRandB32()
	nm.database.(*databasemocks.Plugin).On("GetVerifierByHash", nm.ctx, hash).
		Return(&fftypes.Verifier{Hash: hash, Namespace: "ns1"}, nil)
	res, err := nm.GetVerifierByHash(nm.ctx, "ns1", hash.String())
	assert.NoError(t, err)
	assert.Equal(t, *hash, *res.Hash)
}

func TestGetVerifierByHashNotFound(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	hash := fftypes.NewRandB32()
	nm.database.(*databasemocks.Plugin).On("GetVerifierByHash", nm.ctx, hash).Return(nil, nil)
	_, err := nm.GetVerifierByHash(nm.ctx, "ns1", hash.String())
	assert.Regexp(t, "FF10109", err)
}

func TestGetVerifierByHashError(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	hash := fftypes.NewRandB32()
	nm.database.(*databasemocks.Plugin).On("GetVerifierByHash", nm.ctx, hash).Return(nil, fmt.Errorf("pop"))
	_, err := nm.GetVerifierByHash(nm.ctx, "ns1", hash.String())
	assert.Regexp(t, "pop", err)
}

func TestGetVerifierByHashBadNS(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	hash := fftypes.NewRandB32()
	nm.database.(*databasemocks.Plugin).On("GetVerifierByHash", nm.ctx, hash).
		Return(&fftypes.Verifier{Hash: hash, Namespace: "ns1"}, nil)
	_, err := nm.GetVerifierByHash(nm.ctx, "ns2", hash.String())
	assert.Regexp(t, "FF10109", err)
}

func TestGetVerifierByHashBadUUID(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	_, err := nm.GetVerifierByHash(nm.ctx, "ns1", "bad")
	assert.Regexp(t, "FF10232", err)
}

func TestGetVerifierByDIDOk(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentities", nm.ctx, mock.MatchedBy(func(f database.Filter) bool {
		fi, err := f.Finalize()
		assert.NoError(t, err)
		v, err := fi.Children[0].Value.Value()
		assert.NoError(t, err)
		return v == "did:firefly:org/abc"
	})).
		Return([]*fftypes.Identity{testOrg("abc")}, nil, nil)
	id, err := nm.GetIdentityByDID(nm.ctx, "did:firefly:org/abc")
	assert.NoError(t, err)
	assert.Equal(t, "did:firefly:org/abc", id.DID)
}

func TestGetVerifierByDIDNotFound(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentities", nm.ctx, mock.Anything).
		Return([]*fftypes.Identity{}, nil, nil)
	id, err := nm.GetIdentityByDID(nm.ctx, "did:firefly:org/abc")
	assert.Regexp(t, "FF10109", err)
	assert.Nil(t, id)
}

func TestGetVerifierByDIDNotErr(t *testing.T) {
	nm, cancel := newTestNetworkmap(t)
	defer cancel()
	nm.database.(*databasemocks.Plugin).On("GetIdentities", nm.ctx, mock.Anything).
		Return(nil, nil, fmt.Errorf("pop"))
	id, err := nm.GetIdentityByDID(nm.ctx, "did:firefly:org/abc")
	assert.Regexp(t, "pop", err)
	assert.Nil(t, id)
}
