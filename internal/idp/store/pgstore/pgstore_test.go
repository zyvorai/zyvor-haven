// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/pgstore"
	"github.com/zyvorai/haven/internal/idp/store/storetest"
)

func dsn(t *testing.T) string {
	d := os.Getenv("HAVEN_TEST_PG_DSN")
	if d == "" {
		t.Skip("HAVEN_TEST_PG_DSN not set")
	}
	return d
}

// reset wipes all data (realms cascade) but keeps the schema.
func reset(t *testing.T, s *pgstore.Store) {
	t.Helper()
	rs, err := s.ListRealms(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if err := s.DeleteRealm(context.Background(), r.Name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConformance(t *testing.T) {
	d := dsn(t)
	s, err := pgstore.Open(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	storetest.Run(t, func(t *testing.T) core.Store {
		reset(t, s)
		t.Cleanup(func() { reset(t, s) })
		return s
	})
}

// Concurrent replicas starting at once must all migrate cleanly.
func TestConcurrentOpen(t *testing.T) {
	d := dsn(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := pgstore.Open(context.Background(), d)
			if err != nil {
				errs <- err
				return
			}
			s.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
