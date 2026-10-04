// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zyvorai/haven/internal/api"
	"github.com/zyvorai/haven/internal/auth"
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

	kc, err := keycloak.NewManagerFromEnv()
	if err != nil {
		log.Fatalf("keycloak client: %v", err)
	}

	pr, err := plane.NewReaderFromEnv()
	if err != nil {
		log.Printf("plane reader: %v", err)
	}

	if realm := os.Getenv("HAVEN_BOOTSTRAP_REALM"); realm != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := kc.Client().BootstrapRealm(ctx, realm); err != nil {
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
