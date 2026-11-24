// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import (
	"bufio"
	// #nosec G505 -- SHA-1 is the HIBP corpus identifier, not a security primitive
	"crypto/sha1" //nolint:gosec // identifier of a corpus entry, not a security primitive
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync/atomic"
)

// Bloom is a bloom filter over SHA-1 digests of breached passwords. It has no
// false negatives; the false-positive rate is chosen at build time. The k
// probe positions are derived from the digest itself (double hashing over its
// first 16 bytes), so no further hashing is needed.
type Bloom struct {
	k    uint8
	m    uint64 // bits
	n    uint64 // entries added at build time
	bits []byte
}

const (
	bloomMagic  = "HVBF1\n"
	bloomHeader = len(bloomMagic) + 1 + 8 + 8
	// maxBloomBits caps a filter at 4 GiB so a corrupt header cannot allocate more.
	maxBloomBits = 1 << 35
)

// NewBloom sizes a filter for n expected entries at false-positive rate fp.
func NewBloom(n int, fp float64) (*Bloom, error) {
	if !(fp > 0 && fp < 1) {
		return nil, errors.New("false-positive rate must be in (0,1)")
	}
	if n < 1 {
		n = 1
	}
	mf := math.Ceil(-float64(n) * math.Log(fp) / (math.Ln2 * math.Ln2))
	if mf > maxBloomBits {
		return nil, errors.New("filter would exceed 4 GiB; raise the false-positive rate")
	}
	m := uint64(mf)
	if m < 64 {
		m = 64
	}
	k := int(math.Round(float64(m) / float64(n) * math.Ln2))
	if k < 1 {
		k = 1
	}
	if k > 32 {
		k = 32
	}
	return &Bloom{k: uint8(k), m: m, bits: make([]byte, (m+7)/8)}, nil
}

func (b *Bloom) probes(d [20]byte) (h1, h2 uint64) {
	h1 = binary.BigEndian.Uint64(d[0:8])
	h2 = binary.BigEndian.Uint64(d[8:16]) | 1
	return
}

// AddDigest adds a SHA-1 digest.
func (b *Bloom) AddDigest(d [20]byte) {
	h1, h2 := b.probes(d)
	for i := uint64(0); i < uint64(b.k); i++ {
		p := (h1 + i*h2) % b.m
		b.bits[p>>3] |= 1 << (p & 7)
	}
	b.n++
}

// HasDigest reports whether d may be in the set.
func (b *Bloom) HasDigest(d [20]byte) bool {
	h1, h2 := b.probes(d)
	for i := uint64(0); i < uint64(b.k); i++ {
		p := (h1 + i*h2) % b.m
		if b.bits[p>>3]&(1<<(p&7)) == 0 {
			return false
		}
	}
	return true
}

// Has reports whether the exact plaintext pw may be in the set.
// #nosec G401 -- SHA-1 is the HIBP corpus identifier, not a security primitive
func (b *Bloom) Has(pw string) bool { return b.HasDigest(sha1.Sum([]byte(pw))) } //nolint:gosec

// Len is the number of entries added at build time; K the probe count; Bits
// the filter size in bits.
func (b *Bloom) Len() uint64  { return b.n }
func (b *Bloom) K() int       { return int(b.k) }
func (b *Bloom) Bits() uint64 { return b.m }

// MarshalBinary serialises the filter: magic, k, m, n, bit array.
func (b *Bloom) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, bloomHeader+len(b.bits))
	out = append(out, bloomMagic...)
	out = append(out, b.k)
	out = binary.BigEndian.AppendUint64(out, b.m)
	out = binary.BigEndian.AppendUint64(out, b.n)
	return append(out, b.bits...), nil
}

// UnmarshalBloom parses MarshalBinary output, validating the header.
func UnmarshalBloom(data []byte) (*Bloom, error) {
	if len(data) < bloomHeader || string(data[:len(bloomMagic)]) != bloomMagic {
		return nil, errors.New("not a haven breach filter")
	}
	p := data[len(bloomMagic):]
	k, m, n := p[0], binary.BigEndian.Uint64(p[1:9]), binary.BigEndian.Uint64(p[9:17])
	if k < 1 || k > 32 || m < 64 || m > maxBloomBits {
		return nil, errors.New("breach filter header is invalid")
	}
	body := data[bloomHeader:]
	if uint64(len(body)) != (m+7)/8 {
		return nil, errors.New("breach filter is truncated or has trailing bytes")
	}
	return &Bloom{k: k, m: m, n: n, bits: append([]byte(nil), body...)}, nil
}

// parseCorpusLine turns one input line into a SHA-1 digest. A line that is 40
// hex characters (optionally followed by ":count", the haveibeenpwned format)
// is taken as a digest; anything else is hashed as a plaintext password. A
// plaintext password that happens to be 40 hex characters is therefore
// treated as a digest. Blank lines are skipped.
func parseCorpusLine(line string) (d [20]byte, ok bool) {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return d, false
	}
	h := line
	if i := strings.IndexByte(h, ':'); i == 40 {
		h = h[:i]
	}
	if len(h) == 40 {
		if raw, err := hex.DecodeString(h); err == nil {
			copy(d[:], raw)
			return d, true
		}
	}
	// #nosec G401 -- SHA-1 is the HIBP corpus identifier, not a security primitive
	return sha1.Sum([]byte(line)), true //nolint:gosec
}

// BuildBreachFilter reads lines of plaintext passwords or SHA-1 hex digests
// and returns a serialised filter with the given false-positive rate. It holds
// 20 bytes per input line in memory while building.
func BuildBreachFilter(r io.Reader, fpRate float64) ([]byte, error) {
	var digests [][20]byte
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if d, ok := parseCorpusLine(sc.Text()); ok {
			digests = append(digests, d)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(digests) == 0 {
		return nil, errors.New("no entries in input")
	}
	b, err := NewBloom(len(digests), fpRate)
	if err != nil {
		return nil, err
	}
	for _, d := range digests {
		b.AddDigest(d)
	}
	return b.MarshalBinary()
}

// LoadBreachFilter reads a filter produced by BuildBreachFilter.
func LoadBreachFilter(path string) (*Bloom, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied breach filter path
	if err != nil {
		return nil, fmt.Errorf("load breach filter: %w", err)
	}
	b, err := UnmarshalBloom(data)
	if err != nil {
		return nil, fmt.Errorf("load breach filter %s: %w", path, err)
	}
	return b, nil
}

var breachFilter atomic.Pointer[Bloom]

// SetBreachFilter registers the filter used by the notBreached() policy term;
// nil unregisters it. Safe for concurrent use. Until a filter is registered,
// notBreached() accepts every password.
func SetBreachFilter(b *Bloom) { breachFilter.Store(b) }

// IsBreached reports whether pw is in the registered filter (false when none).
func IsBreached(pw string) bool {
	b := breachFilter.Load()
	return b != nil && b.Has(pw)
}
