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
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/hyperledger/firefly/internal/i18n"
	"github.com/hyperledger/firefly/internal/log"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
)

var (
	contractMethodsColumns = []string{
		"id",
		"interface_id",
		"namespace",
		"name",
		"params",
		"returns",
	}
	contractMethodsQueryColumns = []string{
		"id",
		"name",
		"params",
		"returns",
	}
	contractMethodsFilterFieldMap = map[string]string{}
)

func (s *SQLCommon) InsertContractMethod(ctx context.Context, ns string, contractID *fftypes.UUID, method *fftypes.FFIMethod) (err error) {
	ctx, tx, autoCommit, err := s.beginOrUseTx(ctx)
	if err != nil {
		return err
	}
	defer s.rollbackTx(ctx, tx, autoCommit)

	rows, _, err := s.queryTx(ctx, tx,
		sq.Select("id").
			From("contractmethods").
			Where(sq.And{sq.Eq{"interface_id": contractID}, sq.Eq{"namespace": ns}, sq.Eq{"name": method.Name}}),
	)
	if err != nil {
		return err
	}
	existing := rows.Next()
	rows.Close()

	if existing {
		if err = s.updateTx(ctx, tx,
			sq.Update("contractmethods").
				Set("interface_id", contractID).
				Set("namespace", ns).
				Set("name", method.Name).
				Set("params", method.Params).
				Set("returns", method.Returns),
			func() {
				s.callbacks.UUIDCollectionNSEvent(database.CollectionContractInterfaces, fftypes.ChangeEventTypeUpdated, ns, contractID)
			},
		); err != nil {
			return err
		}
	} else {
		if _, err = s.insertTx(ctx, tx,
			sq.Insert("contractmethods").
				Columns(contractMethodsColumns...).
				Values(
					method.ID,
					contractID,
					ns,
					method.Name,
					method.Params,
					method.Returns,
				),
			func() {
				s.callbacks.UUIDCollectionNSEvent(database.CollectionContractInterfaces, fftypes.ChangeEventTypeCreated, ns, contractID)
			},
		); err != nil {
			return err
		}
	}

	return s.commitTx(ctx, tx, autoCommit)
}

func (s *SQLCommon) contractMethodResult(ctx context.Context, row *sql.Rows) (*fftypes.FFIMethod, error) {
	method := fftypes.FFIMethod{}
	err := row.Scan(
		&method.ID,
		&method.Name,
		&method.Params,
		&method.Returns,
	)
	if err != nil {
		return nil, i18n.WrapError(ctx, err, i18n.MsgDBReadErr, "contractmethods")
	}
	return &method, nil
}

func (s *SQLCommon) getContractMethodPred(ctx context.Context, desc string, pred interface{}) (*fftypes.FFIMethod, error) {
	rows, _, err := s.query(ctx,
		sq.Select(contractMethodsQueryColumns...).
			From("contractmethods").
			Where(pred),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		log.L(ctx).Debugf("Contract method '%s' not found", desc)
		return nil, nil
	}

	ci, err := s.contractMethodResult(ctx, rows)
	if err != nil {
		return nil, err
	}

	return ci, nil
}

func (s *SQLCommon) GetContractMethods(ctx context.Context, ns string, filter database.Filter) (methods []*fftypes.FFIMethod, res *database.FilterResult, err error) {
	query, fop, fi, err := s.filterSelect(ctx, "", sq.Select(contractMethodsQueryColumns...).From("contractmethods").Where(sq.Eq{"namespace": ns}), filter, contractMethodsFilterFieldMap, []interface{}{"sequence"})
	if err != nil {
		return nil, nil, err
	}

	rows, tx, err := s.query(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		ci, err := s.contractMethodResult(ctx, rows)
		if err != nil {
			return nil, nil, err
		}
		methods = append(methods, ci)
	}

	return methods, s.queryRes(ctx, tx, "contract_methods", fop, fi), err

}

func (s *SQLCommon) GetContractMethodByName(ctx context.Context, ns, contractID, name string) (*fftypes.FFIMethod, error) {
	return s.getContractMethodPred(ctx, ns+":"+name, sq.And{sq.Eq{"namespace": ns}, sq.Eq{"interface_id": contractID}, sq.Eq{"name": name}})
}
