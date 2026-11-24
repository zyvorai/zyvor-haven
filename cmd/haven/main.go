// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Command haven is the command-line client for haven-idp: OAuth 2.0 Device
// Authorization Grant login, a token helper for scripts, and a kubectl exec
// credential plugin. See docs/haven-cli.md.
//
//	haven login --issuer URL --client-id ID
//	haven token [--id-token]
//	haven whoami [--json]
//	haven logout
//	haven exec-credential --issuer URL --client-id ID
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/zyvorai/haven/internal/havencli"
)

// version is set with -ldflags "-X main.version=...".
var version = ""

func main() {
	switch {
	case version != "":
		havencli.Version = version
	default:
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			havencli.Version = bi.Main.Version
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := havencli.Run(ctx, os.Args[1:], havencli.DefaultEnv())
	stop()
	os.Exit(code)
}
