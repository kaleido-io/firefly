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
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/fftypes"
	"github.com/stretchr/testify/assert"
)

var (
	emptyHistogramResult = []*fftypes.ChartHistogram{
		{
			Count:     "0",
			Timestamp: fftypes.UnixTime(1000000000),
			Types:     make([]*fftypes.ChartHistogramType, 0),
		},
	}
	expectedHistogramResult = []*fftypes.ChartHistogram{
		{
			Count:     "10",
			Timestamp: fftypes.UnixTime(1000000000),
			Types: []*fftypes.ChartHistogramType{
				{
					Count: "5",
					Type:  "typeA",
				},
				{
					Count: "5",
					Type:  "typeB",
				},
			},
		},
	}

	mockHistogramInterval = []fftypes.ChartHistogramInterval{
		{
			StartTime: fftypes.UnixTime(1000000000),
			EndTime:   fftypes.UnixTime(1000000001),
		},
	}
	validCollections = []string{
		"events",
		"messages",
		"operations",
		"transactions",
		"tokentransfers",
	}
)

func TestGetChartHistogramInvalidCollectionName(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectBegin()
	_, err := s.GetChartHistogram(context.Background(), "ns1", []fftypes.ChartHistogramInterval{}, database.CollectionName("abc"))
	assert.Regexp(t, "FF10301", err)
}

func TestGetChartHistogramValidCollectionName(t *testing.T) {
	for i := range validCollections {
		s, mock := newMockProvider().init()
		mock.ExpectQuery("SELECT DISTINCT .*").WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow("typeA").AddRow("typeB"))
		mock.ExpectQuery("SELECT .*").WillReturnRows(sqlmock.NewRows([]string{"case_0", "case_1"}).AddRow("5", "5"))

		histogram, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName(validCollections[i]))

		assert.NoError(t, err)
		assert.Equal(t, histogram, expectedHistogramResult)
		assert.NoError(t, mock.ExpectationsWereMet())
	}
}

func TestGetChartHistogramsQueryFail(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectQuery("SELECT DISTINCT .*").WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow("typeA").AddRow("typeB"))
	mock.ExpectQuery("SELECT *").WillReturnError(fmt.Errorf("pop"))

	_, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName("messages"))
	assert.Regexp(t, "FF10115", err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetChartHistogramQueryFailBadDistinctTypes(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectQuery("SELECT DISTINCT .*").WillReturnError(fmt.Errorf("pop"))

	_, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName("messages"))
	assert.Regexp(t, "FF10115", err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetChartHistogramScanFailInvalidRowType(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectQuery("SELECT DISTINCT .*").WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow(nil).AddRow("typeB"))

	_, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName("messages"))
	assert.Regexp(t, "FF10121", err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetChartHistogramScanFailTooManyCols(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectQuery("SELECT DISTINCT .*").WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow("typeA").AddRow("typeB"))
	mock.ExpectQuery("SELECT .*").WillReturnRows(sqlmock.NewRows([]string{"case_0", "case_1", "unexpected_col"}).AddRow("one", "two", "three"))

	_, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName("messages"))
	assert.Regexp(t, "FF10121", err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetChartHistogramFailStringToIntConversion(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectQuery("SELECT DISTINCT .*").WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow("typeA").AddRow("typeB"))
	mock.ExpectQuery("SELECT .*").WillReturnRows(sqlmock.NewRows([]string{"case_0", "case_1"}).AddRow("5", "NotInt"))

	_, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName("messages"))
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetChartHistogramSuccessNoRows(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectQuery("SELECT DISTINCT .*").WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow("typeA").AddRow("typeB"))
	mock.ExpectQuery("SELECT .*").WillReturnRows(sqlmock.NewRows([]string{"case_0", "case_1"}))

	histogram, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName("messages"))
	assert.NoError(t, err)
	assert.Equal(t, emptyHistogramResult, histogram)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetChartHistogramSuccess(t *testing.T) {
	s, mock := newMockProvider().init()
	mock.ExpectQuery("SELECT DISTINCT .*").WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow("typeA").AddRow("typeB"))
	mock.ExpectQuery("SELECT .*").WillReturnRows(sqlmock.NewRows([]string{"case_0", "case_1"}).AddRow("5", "5"))

	histogram, err := s.GetChartHistogram(context.Background(), "ns1", mockHistogramInterval, database.CollectionName("messages"))

	assert.NoError(t, err)
	assert.Equal(t, expectedHistogramResult, histogram)
	assert.NoError(t, mock.ExpectationsWereMet())
}
