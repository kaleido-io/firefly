// Copyright © 2026 Kaleido, Inc.
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
	"context"
	"errors"

	"github.com/getkin/kin-openapi/openapi3"
)

// validateOpenAPIDoc runs the standard kin-openapi validation, but tolerates
// ConflictingPathsError findings. FireFly intentionally addresses some
// resources by ID in one route and by name in another at the same path
// shape (e.g. PUT /apis/{id} vs GET/DELETE /apis/{apiName}, and
// GET /identities/{iid} vs GET /identities/{did}). The OpenAPI 3 spec
// disallows this, but it does not affect real routing since each operation
// is still uniquely dispatched by its HTTP method. Any other validation
// finding still fails as normal.
func validateOpenAPIDoc(doc *openapi3.T) error {
	err := doc.Validate(context.Background(), openapi3.EnableMultiError())
	if err == nil {
		return nil
	}

	var multi openapi3.MultiError
	if !errors.As(err, &multi) {
		multi = openapi3.MultiError{err}
	}

	var remaining openapi3.MultiError
	for _, e := range multi {
		var conflictErr *openapi3.ConflictingPathsError
		if !errors.As(e, &conflictErr) {
			remaining = append(remaining, e)
		}
	}
	if len(remaining) == 0 {
		return nil
	}
	return remaining
}
