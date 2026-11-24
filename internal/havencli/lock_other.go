// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//go:build !unix

package havencli

import (
	"context"
	"sync"
	"time"
)

// On platforms without flock (Windows) the lock is best effort: it
// serialises goroutines of this process only. Two separate haven processes
// refreshing at the same instant can still race there; see docs/haven-cli.md.
var procLock sync.Mutex

func lockFile(ctx context.Context, _ string, _ time.Duration) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	procLock.Lock()
	return procLock.Unlock, nil
}

func runtimeHasUnixModes() bool { return false }
