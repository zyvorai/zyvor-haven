// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors a Provider's failures can match with errors.Is.
var (
	ErrNotFound    = errors.New("idp: not found")
	ErrConflict    = errors.New("idp: already exists")
	ErrUnsupported = errors.New("idp: not supported by this provider")
)

// StatusError is a rejection by the backend. Code is the HTTP status the API
// should relay and Body is the backend's (possibly sensitive) response, which
// callers must redact before showing it.
type StatusError struct {
	Code int
	Body []byte
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("identity backend returned %d: %s", e.Code, e.Body)
}

// Is maps well-known codes onto the sentinels.
func (e *StatusError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Code == http.StatusNotFound
	case ErrConflict:
		return e.Code == http.StatusConflict
	}
	return false
}

// AsStatus returns the StatusError in err's chain, if any.
func AsStatus(err error) *StatusError {
	var se *StatusError
	if errors.As(err, &se) {
		return se
	}
	return nil
}

// CheckStatus converts a raw (code, body, err) result into an error: transport
// errors pass through, codes >= 300 become *StatusError.
func CheckStatus(code int, body []byte, err error) error {
	if err != nil {
		return err
	}
	if code >= 300 {
		return &StatusError{Code: code, Body: body}
	}
	return nil
}
