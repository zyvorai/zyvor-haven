// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//go:build nativeidp

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/native"
)

func newNativeBackend() (idp.Backend, error) {
	url := strings.TrimRight(strings.TrimSpace(os.Getenv("HAVEN_IDP_URL")), "/")
	if url == "" {
		return nil, errors.New("HAVEN_IDP_URL is required for the native backend")
	}
	clientID := os.Getenv("HAVEN_IDP_ADMIN_CLIENT_ID")
	if clientID == "" {
		clientID = "haven-admin"
	}
	secret, err := secretFromEnv("HAVEN_IDP_ADMIN_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, errors.New("HAVEN_IDP_ADMIN_CLIENT_SECRET or _FILE is required for the native backend")
	}
	c := native.New(native.Config{
		BaseURL:      url,
		Realm:        os.Getenv("HAVEN_IDP_ADMIN_REALM"),
		ClientID:     clientID,
		ClientSecret: secret,
	})
	return idp.NewStaticBackend(c, c.BaseURL(), c.User()), nil
}
