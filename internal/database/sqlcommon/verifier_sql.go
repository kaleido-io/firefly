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
	verifierColumns = []string{
		"id",
		"identity",
		"vtype",
		"namespace",
		"value",
		"created",
	}
	verifierFilterFieldMap = map[string]string{
		"type": "vtype",
	}
)

func (s *SQLCommon) attemptVerifierUpdate(ctx context.Context, tx *txWrapper, verifier *fftypes.Verifier) (int64, error) {
	return s.updateTx(ctx, tx,
		sq.Update("verifiers").
			Set("identity", verifier.Identity).
			Set("vtype", verifier.Type).
			Set("namespace", verifier.Namespace).
			Set("value", verifier.Value).
			Where(sq.Eq{
				"id": verifier.ID,
			}),
		func() {
			s.callbacks.UUIDCollectionNSEvent(database.CollectionVerifiers, fftypes.ChangeEventTypeUpdated, verifier.Namespace, verifier.ID)
		})
}

func (s *SQLCommon) attemptVerifierInsert(ctx context.Context, tx *txWrapper, verifier *fftypes.Verifier) (err error) {
	verifier.Created = fftypes.Now()
	_, err = s.insertTx(ctx, tx,
		sq.Insert("verifiers").
			Columns(verifierColumns...).
			Values(
				verifier.ID,
				verifier.Identity,
				verifier.Type,
				verifier.Namespace,
				verifier.Value,
				verifier.Created,
			),
		func() {
			s.callbacks.UUIDCollectionNSEvent(database.CollectionVerifiers, fftypes.ChangeEventTypeCreated, verifier.Namespace, verifier.ID)
		})
	return err
}

func (s *SQLCommon) UpsertVerifier(ctx context.Context, verifier *fftypes.Verifier, optimization database.UpsertOptimization) (err error) {
	ctx, tx, autoCommit, err := s.beginOrUseTx(ctx)
	if err != nil {
		return err
	}
	defer s.rollbackTx(ctx, tx, autoCommit)

	optimized := false
	if optimization == database.UpsertOptimizationNew {
		opErr := s.attemptVerifierInsert(ctx, tx, verifier)
		optimized = opErr == nil
	} else if optimization == database.UpsertOptimizationExisting {
		rowsAffected, opErr := s.attemptVerifierUpdate(ctx, tx, verifier)
		optimized = opErr == nil && rowsAffected == 1
	}

	if !optimized {
		// Do a select within the transaction to detemine if the UUID already exists
		msgRows, _, err := s.queryTx(ctx, tx,
			sq.Select("id").
				From("verifiers").
				Where(sq.Eq{"id": verifier.ID}),
		)
		if err != nil {
			return err
		}
		existing := msgRows.Next()
		msgRows.Close()

		if existing {
			// Update the verifier
			if _, err = s.attemptVerifierUpdate(ctx, tx, verifier); err != nil {
				return err
			}
		} else {
			if err = s.attemptVerifierInsert(ctx, tx, verifier); err != nil {
				return err
			}
		}
	}

	return s.commitTx(ctx, tx, autoCommit)
}

func (s *SQLCommon) verifierResult(ctx context.Context, row *sql.Rows) (*fftypes.Verifier, error) {
	verifier := fftypes.Verifier{}
	err := row.Scan(
		&verifier.ID,
		&verifier.Identity,
		&verifier.Type,
		&verifier.Namespace,
		&verifier.Value,
		&verifier.Created,
	)
	if err != nil {
		return nil, i18n.WrapError(ctx, err, i18n.MsgDBReadErr, "verifiers")
	}
	return &verifier, nil
}

func (s *SQLCommon) getVerifierPred(ctx context.Context, desc string, pred interface{}) (verifier *fftypes.Verifier, err error) {

	rows, _, err := s.query(ctx,
		sq.Select(verifierColumns...).
			From("verifiers").
			Where(pred),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		log.L(ctx).Debugf("Verifier '%s' not found", desc)
		return nil, nil
	}

	return s.verifierResult(ctx, rows)
}

func (s *SQLCommon) GetVerifierByValue(ctx context.Context, vType fftypes.VerifierType, namespace, value string) (verifier *fftypes.Verifier, err error) {
	return s.getVerifierPred(ctx, value, sq.Eq{"vtype": vType, "namespace": namespace, "value": value})
}

func (s *SQLCommon) GetVerifierByID(ctx context.Context, id *fftypes.UUID) (verifier *fftypes.Verifier, err error) {
	return s.getVerifierPred(ctx, id.String(), sq.Eq{"id": id})
}

func (s *SQLCommon) GetVerifiers(ctx context.Context, filter database.Filter) (verifiers []*fftypes.Verifier, fr *database.FilterResult, err error) {

	query, fop, fi, err := s.filterSelect(ctx, "", sq.Select(verifierColumns...).From("verifiers"), filter, verifierFilterFieldMap, []interface{}{"sequence"})
	if err != nil {
		return nil, nil, err
	}

	rows, tx, err := s.query(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	verifiers = []*fftypes.Verifier{}
	for rows.Next() {
		d, err := s.verifierResult(ctx, rows)
		if err != nil {
			return nil, nil, err
		}
		verifiers = append(verifiers, d)
	}

	return verifiers, s.queryRes(ctx, tx, "verifiers", fop, fi), err

}

func (s *SQLCommon) UpdateVerifier(ctx context.Context, id *fftypes.UUID, update database.Update) (err error) {

	ctx, tx, autoCommit, err := s.beginOrUseTx(ctx)
	if err != nil {
		return err
	}
	defer s.rollbackTx(ctx, tx, autoCommit)

	query, err := s.buildUpdate(sq.Update("verifiers"), update, verifierFilterFieldMap)
	if err != nil {
		return err
	}
	query = query.Where(sq.Eq{"id": id})

	_, err = s.updateTx(ctx, tx, query, nil /* no change events for filter based updates */)
	if err != nil {
		return err
	}

	return s.commitTx(ctx, tx, autoCommit)
}
