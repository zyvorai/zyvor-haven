// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// VerifyChain checks a stream of raw event JSON values (stdout/file lines or
// webhook array elements, exactly as emitted) from one sink. A Seq of 1 with
// empty Prev starts a new chain (process restart). It returns the number of
// chains seen or the first inconsistency. Tail truncation is not detectable
// from the stream alone.
func VerifyChain(events [][]byte) (chains int, err error) {
	var prevSeq uint64
	var prevHash string
	for i, raw := range events {
		var h struct {
			Seq  uint64 `json:"seq"`
			Prev string `json:"prev"`
		}
		if err := json.Unmarshal(raw, &h); err != nil {
			return chains, fmt.Errorf("event %d: %w", i, err)
		}
		switch {
		case h.Seq == 1 && h.Prev == "":
			chains++
		case i == 0:
			return chains, fmt.Errorf("event 0: stream does not start at seq 1 (head truncated?)")
		case h.Seq != prevSeq+1:
			return chains, fmt.Errorf("event %d: seq %d after %d (gap or reorder)", i, h.Seq, prevSeq)
		case h.Prev != prevHash:
			return chains, fmt.Errorf("event %d: prev mismatch (previous event modified)", i)
		}
		sum := sha256.Sum256(raw)
		prevSeq, prevHash = h.Seq, hex.EncodeToString(sum[:])
	}
	return chains, nil
}
