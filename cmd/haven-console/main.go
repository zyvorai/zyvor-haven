// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/haven/internal/api"
	"github.com/zyvorai/haven/internal/auth"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/keycloak"
	"github.com/zyvorai/haven/internal/plane"
)

//go:embed all:dist
var uiFS embed.FS

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	kc, err := newBackend()
	if err != nil {
		log.Fatalf("identity backend: %v", err)
	}

	pr, err := plane.NewReaderFromEnv()
	if err != nil {
		log.Printf("plane reader: %v", err)
	}

	if realm := os.Getenv("HAVEN_BOOTSTRAP_REALM"); realm != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		var err error
		if c := kc.Client(); c == nil {
			err = errors.New("identity backend not connected")
		} else {
			err = c.BootstrapRealm(ctx, realm)
		}
		if err != nil {
			// #nosec G706 -- realm is operator config from the environment, quoted with %q
			log.Printf("bootstrap realm %q: %v", realm, err)
		} else {
			// #nosec G706 -- realm is operator config from the environment, quoted with %q
			log.Printf("bootstrap realm %q ok", realm)
		}
		cancel()
	}

	apiHandler := api.NewRouter(kc, pr, auth.NewStoreFromEnv())
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)

	dist, err := fs.Sub(uiFS, "dist")
	if err != nil {
		log.Fatalf("embed dist: %v", err)
	}
	fileServer := http.FileServer(http.FS(dist))
	mux.Handle("/", spaHandler(dist, fileServer))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		// #nosec G706 -- addr is operator config from the environment, quoted with %q
		log.Printf("haven-console listening on %q", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// newBackend selects the identity backend via HAVEN_IDP_BACKEND
// ("keycloak" default, or "native").
func newBackend() (idp.Backend, error) {
	switch b := strings.ToLower(strings.TrimSpace(os.Getenv("HAVEN_IDP_BACKEND"))); b {
	case "", "keycloak":
		return keycloak.NewManagerFromEnv()
	case "native":
		return newNativeBackend()
	default:
		return nil, fmt.Errorf("unknown HAVEN_IDP_BACKEND %q (want keycloak or native)", b)
	}
}

// secretFromEnv reads NAME, or the file named by NAME_FILE.
func secretFromEnv(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f) // #nosec G304 G703 -- operator-supplied secret path
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

func spaHandler(dist fs.FS, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			if _, err := fs.Stat(dist, r.URL.Path[1:]); err != nil {
				r2 := r.Clone(r.Context())
				r2.URL.Path = "/"
				next.ServeHTTP(w, r2)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
