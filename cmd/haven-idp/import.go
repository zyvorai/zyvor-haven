// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/configcode"
	"github.com/zyvorai/haven/internal/idp/kcimport"
)

// exitPartial is returned by import-users when some users could not be imported.
const exitPartial = 4

const (
	importBatch     = 500
	maxListedErrors = 100
)

// cmdImport runs import-keycloak or import-users and returns the exit code.
func cmdImport(name string, args []string, io_ cfgIO) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, err := runImport(ctx, name, args, io_)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(io_.Stderr, "haven-idp:", err)
		if code == exitOK {
			code = exitError
		}
	}
	return code
}

func runImport(ctx context.Context, name string, args []string, io_ cfgIO) (int, error) {
	var f cfgFlags
	var realm, outDir string
	fs := newCfgFlagSet(name, &f)
	fs.StringVar(&realm, "realm", "", "target realm name")
	if name == "import-keycloak" {
		fs.StringVar(&outDir, "out-dir", "", "write realm.yaml and users.json here (without it: dry run)")
	}
	if err := fs.Parse(args); err != nil {
		return exitError, fmt.Errorf("%w\n\n%s", err, usage)
	}
	if fs.NArg() > 0 {
		return exitError, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if f.format != "text" && f.format != "json" {
		return exitError, fmt.Errorf("--format must be text or json, got %q", f.format)
	}
	if f.file == "" {
		return exitError, errors.New("-f FILE is required (use - for stdin)")
	}
	if name == "import-keycloak" {
		return runImportKeycloak(f, realm, outDir, io_)
	}
	return runImportUsers(ctx, f, realm, io_)
}

func openInput(path string, io_ cfgIO) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(io_.Stdin), nil
	}
	return os.Open(path) // #nosec G304 -- operator-provided path
}

func runImportKeycloak(f cfgFlags, realm, outDir string, io_ cfgIO) (int, error) {
	if realm != "" && !validRealm(realm) {
		return exitError, fmt.Errorf("--realm %q is not a valid realm name", realm)
	}
	in, err := openInput(f.file, io_)
	if err != nil {
		return exitError, err
	}
	defer func() { _ = in.Close() }()
	res, err := kcimport.Convert(in, kcimport.Options{Realm: realm})
	if err != nil {
		return exitError, fmt.Errorf("%s: %w", f.file, err)
	}
	var yamlOut []byte
	if outDir != "" {
		if yamlOut, err = configcode.Marshal(res.Spec); err != nil {
			return exitError, err
		}
		if err := writeImportFiles(outDir, yamlOut, res.Users); err != nil {
			return exitError, err
		}
	}
	if f.format == "json" {
		return exitOK, writeJSON(io_.Stdout, res.Report)
	}
	printImportReport(io_.Stdout, res.Report)
	if outDir == "" {
		fmt.Fprintln(io_.Stdout, "\nDry run: nothing written. Re-run with --out-dir DIR to write realm.yaml and users.json.")
		return exitOK, nil
	}
	fmt.Fprintf(io_.Stdout, "\nWrote %s (mode 0644) and %s (mode 0600, contains password hashes; guard it).\n",
		filepath.Join(outDir, "realm.yaml"), filepath.Join(outDir, "users.json"))
	fmt.Fprintf(io_.Stdout, "Next: review realm.yaml, then `haven-idp apply -f %s`, then `haven-idp import-users -f %s --realm %s`.\n",
		filepath.Join(outDir, "realm.yaml"), filepath.Join(outDir, "users.json"), res.Spec.Realm)
	return exitOK, nil
}

// writeImportFiles creates DIR/realm.yaml (0644) and DIR/users.json (0600).
// It refuses to overwrite either and removes what it created on failure.
func writeImportFiles(dir string, yamlOut []byte, users []idp.ImportUser) error {
	yp, up := filepath.Join(dir, "realm.yaml"), filepath.Join(dir, "users.json")
	for _, p := range []string{yp, up} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite (remove it or choose another --out-dir)", p)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- users.json carries its own 0600
		return err
	}
	var made []string
	fail := func(err error) error {
		for _, p := range made {
			_ = os.Remove(p)
		}
		return err
	}
	if err := createNew(yp, 0o644, func(w io.Writer) error { _, err := w.Write(yamlOut); return err }); err != nil {
		return fail(err)
	}
	made = append(made, yp)
	if err := createNew(up, 0o600, func(w io.Writer) error { return encodeUsers(w, users) }); err != nil {
		return fail(err)
	}
	return nil
}

func createNew(path string, mode os.FileMode, write func(io.Writer) error) (err error) {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- operator-provided path
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite", path)
		}
		return err
	}
	defer func() {
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err = fh.Chmod(mode); err != nil { // beat a restrictive or permissive umask
		return err
	}
	bw := bufio.NewWriter(fh)
	if err = write(bw); err != nil {
		return err
	}
	return bw.Flush()
}

func encodeUsers(w io.Writer, users []idp.ImportUser) error {
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	for i, u := range users {
		b, err := json.Marshal(u)
		if err != nil {
			return err
		}
		sep := "\n  "
		if i > 0 {
			sep = ",\n  "
		}
		if _, err := io.WriteString(w, sep); err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\n]\n")
	return err
}

func printImportReport(w io.Writer, r kcimport.Report) {
	target := r.TargetRealm
	if r.SourceRealm != "" && r.SourceRealm != target {
		target += " (from " + r.SourceRealm + ")"
	}
	fmt.Fprintf(w, "Keycloak import report for realm %s\n\n", target)
	m := r.Mapped
	fmt.Fprintf(w, "Mapped:    %d roles, %d groups, %d clients\n", m.Roles, m.Groups, m.Clients)
	fmt.Fprintf(w, "Users:     %d (%d with an importable password, %d without: they must reset)\n", m.Users, m.UsersWithPassword, m.UsersWithoutPassword)
	if len(r.NewSecretClients) > 0 {
		fmt.Fprintf(w, "\nNEW client secrets are generated on apply for: %s\n", strings.Join(r.NewSecretClients, ", "))
		fmt.Fprintln(w, "(secrets in the export are never copied; update each application)")
	}
	if len(r.NotMigrated) > 0 {
		fmt.Fprintln(w, "\nNot migrated (no haven-idp equivalent):")
		keys := make([]string, 0, len(r.NotMigrated))
		for k := range r.NotMigrated {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %-24s %d\n", strings.ReplaceAll(k, "_", " "), r.NotMigrated[k])
		}
	}
	if len(r.WarningCounts) > 0 {
		fmt.Fprintln(w, "\nWarnings by code:")
		codes := make([]string, 0, len(r.WarningCounts))
		for c := range r.WarningCounts {
			if strings.HasPrefix(c, "notmigrated.") {
				continue // shown above
			}
			codes = append(codes, c)
		}
		sort.Strings(codes)
		for _, c := range codes {
			fmt.Fprintf(w, "  %-36s %d\n", c, r.WarningCounts[c])
		}
		fmt.Fprintln(w, "\nDetails:")
		for _, x := range r.Warnings {
			if strings.HasPrefix(x.Code, "notmigrated.") {
				continue
			}
			where := ""
			if x.Where != "" {
				where = " [" + x.Where + "]"
			}
			fmt.Fprintf(w, "  %s%s: %s\n", x.Code, where, x.Message)
		}
		if r.WarningsTruncated {
			fmt.Fprintln(w, "  (further warnings of the same code are counted above but not listed; use --format json for counts)")
		}
	}
}

type importUsersJSON struct {
	Realm   string            `json:"realm"`
	Created int               `json:"created"`
	Skipped int               `json:"skipped"`
	Failed  int               `json:"failed"`
	Errors  []idp.ImportError `json:"errors,omitempty"`
	More    int               `json:"moreErrors,omitempty"`
}

func runImportUsers(ctx context.Context, f cfgFlags, realm string, io_ cfgIO) (int, error) {
	if !validRealm(realm) {
		return exitError, errors.New("usage: haven-idp import-users -f users.json --realm NAME [connection flags]")
	}
	in, err := openInput(f.file, io_)
	if err != nil {
		return exitError, err
	}
	defer func() { _ = in.Close() }()
	prov, err := connect(f)
	if err != nil {
		return exitError, err
	}
	imp, ok := prov.(idp.UserImporter)
	if !ok {
		return exitError, errors.New("this identity provider does not support user import (only haven-idp's native server does)")
	}
	out := importUsersJSON{Realm: realm}
	flush := func(batch []idp.ImportUser) error {
		res, err := imp.ImportUsers(ctx, realm, batch)
		if err != nil {
			return fmt.Errorf("import failed after %d created, %d skipped, %d failed: %w", out.Created, out.Skipped, out.Failed, err)
		}
		if res == nil {
			return errors.New("the server returned no result")
		}
		out.Created += res.Created
		out.Skipped += res.Skipped
		for _, e := range res.Errors {
			out.Failed++
			if len(out.Errors) < maxListedErrors {
				out.Errors = append(out.Errors, idp.ImportError{Username: e.Username, Reason: redactReason(e.Reason)})
			} else {
				out.More++
			}
		}
		return nil
	}
	if err := streamUsers(in, importBatch, flush); err != nil {
		return exitError, fmt.Errorf("%s: %w", f.file, err)
	}
	if f.format == "json" {
		err = writeJSON(io_.Stdout, out)
	} else {
		printImportUsers(io_.Stdout, out)
	}
	if err != nil {
		return exitError, err
	}
	if out.Failed > 0 {
		return exitPartial, nil
	}
	return exitOK, nil
}

// redactReason keeps hashes out of anything we print, whatever the server said.
func redactReason(s string) string {
	if strings.Contains(s, "$pbkdf2") || strings.Contains(s, "$argon2") {
		return "[redacted]"
	}
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func printImportUsers(w io.Writer, o importUsersJSON) {
	fmt.Fprintf(w, "Imported users into realm %s\n", o.Realm)
	fmt.Fprintf(w, "  created: %d\n  skipped (already existed): %d\n  failed:  %d\n", o.Created, o.Skipped, o.Failed)
	for _, e := range o.Errors {
		fmt.Fprintf(w, "    - %s: %s\n", e.Username, e.Reason)
	}
	if o.More > 0 {
		fmt.Fprintf(w, "    ... and %d more\n", o.More)
	}
}

// streamUsers reads a JSON array of users, or an object with a "users" array,
// and calls flush with batches of at most size users. Errors never echo the
// content of the file.
func streamUsers(r io.Reader, size int, flush func([]idp.ImportUser) error) error {
	errShape := errors.New(`not a users file: expected a JSON array or {"users":[...]}`)
	errBroken := errors.New("users file is truncated or not valid JSON")
	dec := json.NewDecoder(r)
	batch := make([]idp.ImportUser, 0, size)
	// elems reads array elements; the opening bracket is already consumed.
	elems := func() error {
		for dec.More() {
			var u idp.ImportUser
			if err := dec.Decode(&u); err != nil {
				return errors.New("invalid user entry in users file")
			}
			batch = append(batch, u)
			if len(batch) == size {
				if err := flush(batch); err != nil {
					return err
				}
				batch = batch[:0]
			}
		}
		if _, err := dec.Token(); err != nil {
			return errBroken
		}
		return nil
	}
	t, err := dec.Token()
	if err != nil {
		return errShape
	}
	found := false
	switch d, _ := t.(json.Delim); d {
	case '[':
		found = true
		if err := elems(); err != nil {
			return err
		}
	case '{':
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return errBroken
			}
			if kt != "users" || found {
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return errBroken
				}
				continue
			}
			t, err := dec.Token()
			if err != nil {
				return errBroken
			}
			if d, _ := t.(json.Delim); d != '[' {
				return errors.New(`"users" must be an array`)
			}
			found = true
			if err := elems(); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errBroken
		}
	default:
		return errShape
	}
	if !found {
		return errShape
	}
	if len(batch) > 0 {
		return flush(batch)
	}
	return nil
}
