// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keychain

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// `security -i` reads one command per line of at most ~4 KiB, and a token set
// (access + ID + refresh JWTs) can exceed that. The *Blob functions split a
// value over several items: the first, at the plain account name, starts with
// "hb1.<N>." and carries chunk 0; chunk i lives at account+"#i".
const (
	blobChunk  = 3000
	blobPrefix = "hb1."
	maxChunks  = 22 // 64 KiB
)

func chunkAccount(account string, i int) string {
	if i == 0 {
		return account
	}
	return fmt.Sprintf("%s#%d", account, i)
}

// SetBlob stores a value of up to 64 KiB (same alphabet as Set), chunked.
func (c *Client) SetBlob(ctx context.Context, service, account, secret string) error {
	if err := validSecret(secret); err != nil {
		return err
	}
	var chunks []string
	for rest := secret; ; {
		n := min(blobChunk, len(rest))
		chunks = append(chunks, rest[:n])
		if rest = rest[n:]; rest == "" {
			break
		}
	}
	if len(chunks) > maxChunks {
		return errors.New("keychain blob too large")
	}
	// Write the tail first so a reader never sees a header with missing chunks.
	for i := len(chunks) - 1; i >= 0; i-- {
		v := chunks[i]
		if i == 0 {
			v = fmt.Sprintf("%s%d.%s", blobPrefix, len(chunks), v)
		}
		if err := c.Set(ctx, service, chunkAccount(account, i), v); err != nil {
			return err
		}
	}
	// Drop leftover chunks from a previous, longer value.
	for i := len(chunks); i < maxChunks; i++ {
		if _, err := c.Get(ctx, service, chunkAccount(account, i)); err != nil {
			break
		}
		_ = c.Delete(ctx, service, chunkAccount(account, i))
	}
	return nil
}

func parseHeader(v string) (n int, first string, err error) {
	rest, ok := strings.CutPrefix(v, blobPrefix)
	if !ok {
		return 0, "", errors.New("keychain item is not a haven blob")
	}
	num, first, ok := strings.Cut(rest, ".")
	if !ok {
		return 0, "", errors.New("keychain blob header is malformed")
	}
	if _, err := fmt.Sscanf(num, "%d", &n); err != nil || n < 1 || n > maxChunks || fmt.Sprint(n) != num {
		return 0, "", errors.New("keychain blob header is malformed")
	}
	return n, first, nil
}

// GetBlob reads a value written by SetBlob, or ErrNotFound.
func (c *Client) GetBlob(ctx context.Context, service, account string) (string, error) {
	v, err := c.Get(ctx, service, account)
	if err != nil {
		return "", err
	}
	n, first, err := parseHeader(v)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(first)
	for i := 1; i < n; i++ {
		p, err := c.Get(ctx, service, chunkAccount(account, i))
		if errors.Is(err, ErrNotFound) {
			return "", errors.New("keychain blob is incomplete")
		}
		if err != nil {
			return "", err
		}
		b.WriteString(p)
	}
	return b.String(), nil
}

// DeleteBlob removes a blob and all its chunks; a missing blob is not an error.
func (c *Client) DeleteBlob(ctx context.Context, service, account string) error {
	n := 1
	v, err := c.Get(ctx, service, account)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil
	case err != nil:
		return err
	}
	if hn, _, perr := parseHeader(v); perr == nil {
		n = hn
	}
	var first error
	for i := n - 1; i >= 0; i-- {
		if err := c.Delete(ctx, service, chunkAccount(account, i)); err != nil && first == nil {
			first = err
		}
	}
	return first
}
