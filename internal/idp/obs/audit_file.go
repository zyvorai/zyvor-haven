// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// lineBackend writes one JSON object per line.
type lineBackend struct {
	mu sync.Mutex
	w  io.Writer
	f  *os.File // non-nil for file sinks
}

func (b *lineBackend) send(_ context.Context, lines [][]byte) error {
	var buf []byte
	for _, l := range lines {
		buf = append(buf, l...)
		buf = append(buf, '\n')
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.w.Write(buf)
	return err
}

func (b *lineBackend) close() error {
	if b.f == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	err := b.f.Sync()
	if cerr := b.f.Close(); err == nil {
		err = cerr
	}
	return err
}

func newStdoutSink(opts AuditOptions, m *auditMetrics) (AuditSink, error) {
	w := opts.stdout
	if w == nil {
		w = os.Stdout
	}
	return newSink("stdout", opts, m, &lineBackend{w: w}, 100, 0), nil
}

func newFileSink(path string, opts AuditOptions, m *auditMetrics) (AuditSink, error) {
	if path == "" {
		return nil, fmt.Errorf("audit file sink: empty path")
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit file sink: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("audit file sink: %s is a symlink; refusing", path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit file sink: %w", err)
	}
	// Close the Lstat/Open race: the opened file must be the one at path.
	fi, err1 := f.Stat()
	li, err2 := os.Lstat(path)
	if err1 != nil || err2 != nil || li.Mode()&os.ModeSymlink != 0 || !os.SameFile(fi, li) {
		_ = f.Close()
		return nil, fmt.Errorf("audit file sink: %s changed while opening; refusing", path)
	}
	return newSink("file", opts, m, &lineBackend{w: f, f: f}, 100, 0), nil
}
