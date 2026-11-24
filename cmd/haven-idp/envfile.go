// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// parseEnvFile reads KEY=VALUE lines. Blank lines and #-comments are skipped,
// an optional `export ` prefix and one pair of surrounding quotes are removed.
// There is no interpolation: values are used verbatim.
func parseEnvFile(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, sc.Err()
}

// loadEnvFile sets variables from the file that are not already set, so real
// environment (and orchestrator-provided secrets) always win.
func loadEnvFile(path string) error {
	f, err := os.Open(path) // #nosec G304 G703 -- operator-provided path
	if err != nil {
		return fmt.Errorf("env file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "haven-idp: warning: %s is readable by other users (mode %o); run chmod 600\n", path, st.Mode().Perm())
	}
	kv, err := parseEnvFile(f)
	if err != nil {
		return fmt.Errorf("env file %s: %w", path, err)
	}
	for k, v := range kv {
		if _, set := os.LookupEnv(k); !set {
			if err := os.Setenv(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}
