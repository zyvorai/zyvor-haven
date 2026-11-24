// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package webauthn_test

import (
	"bytes"
	"errors"
	"reflect"
	"runtime"
	"testing"

	. "github.com/zyvorai/haven/internal/idp/webauthn"
	wt "github.com/zyvorai/haven/internal/idp/webauthn/webauthntest"
)

func TestCBORDecodeValid(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []byte
		want any
	}{
		"uint0":      {[]byte{0x00}, int64(0)},
		"uint23":     {[]byte{0x17}, int64(23)},
		"uint24":     {[]byte{0x18, 0x18}, int64(24)},
		"uint1000":   {[]byte{0x19, 0x03, 0xe8}, int64(1000)},
		"neg1":       {[]byte{0x20}, int64(-1)},
		"neg257":     {[]byte{0x39, 0x01, 0x00}, int64(-257)},
		"bytes":      {[]byte{0x43, 1, 2, 3}, []byte{1, 2, 3}},
		"text":       {[]byte{0x63, 'a', 'b', 'c'}, "abc"},
		"false":      {[]byte{0xf4}, false},
		"true":       {[]byte{0xf5}, true},
		"null":       {[]byte{0xf6}, nil},
		"array":      {[]byte{0x82, 0x01, 0x02}, []any{int64(1), int64(2)}},
		"map":        {wt.Map(wt.Pair{K: wt.Text("a"), V: wt.Int(1)}, wt.Pair{K: wt.Int(-2), V: wt.Bytes([]byte{9})}), Map{"a": int64(1), int64(-2): []byte{9}}},
		"max int64":  {[]byte{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, int64(1<<63 - 1)},
		"nested map": {wt.Map(wt.Pair{K: wt.Text("m"), V: wt.Map()}), Map{"m": Map{}}},
	} {
		got, err := DecodeCBOR(tc.in)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %#v, %v; want %#v", name, got, err, tc.want)
		}
	}
}

func TestCBORDecodeRejects(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, 20)
	deep = append(deep, 0x00)
	bigArray := append([]byte{0x98, 65}, bytes.Repeat([]byte{0}, 65)...)
	for name, in := range map[string][]byte{
		"empty":               {},
		"truncated int":       {0x19, 0x01},
		"truncated string":    {0x43, 1, 2},
		"huge byte string":    {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"huge text length":    {0x7a, 0xff, 0xff, 0xff, 0xff, 'x'},
		"huge array count":    {0x9a, 0xff, 0xff, 0xff, 0xff},
		"huge map count":      {0xba, 0xff, 0xff, 0xff, 0xff},
		"array over item cap": bigArray,
		"indefinite bytes":    {0x5f, 0x41, 0x01, 0xff},
		"indefinite array":    {0x9f, 0x01, 0xff},
		"indefinite map":      {0xbf, 0xff},
		"reserved ai":         {0x1c},
		"tag":                 {0xc1, 0x01},
		"float16":             {0xf9, 0x3c, 0x00},
		"float64":             {0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0},
		"undefined":           {0xf7},
		"simple 16":           {0xf0},
		"uint over int64":     {0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"neg over int64":      {0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"duplicate key":       {0xa2, 0x01, 0x01, 0x01, 0x02},
		"duplicate text key":  wt.Map(wt.Pair{K: wt.Text("a"), V: wt.Int(1)}, wt.Pair{K: wt.Text("a"), V: wt.Int(2)}),
		"bytes as key":        wt.Map(wt.Pair{K: wt.Bytes([]byte{1}), V: wt.Int(1)}),
		"map missing value":   {0xa1, 0x01},
		"trailing data":       {0x01, 0x02},
		"nesting too deep":    deep,
		"truncated map":       {0xa2, 0x01, 0x02},
	} {
		if _, err := DecodeCBOR(in); !errors.Is(err, ErrCBOR) {
			t.Errorf("%s: want ErrCBOR, got %v", name, err)
		}
	}
}

func TestCBORPrefix(t *testing.T) {
	in := append(wt.Map(wt.Pair{K: wt.Int(1), V: wt.Int(2)}), 0xde, 0xad)
	v, n, err := DecodeCBORPrefix(in)
	if err != nil || n != len(in)-2 || !reflect.DeepEqual(v, Map{int64(1): int64(2)}) {
		t.Fatalf("%v %d %v", v, n, err)
	}
}

// The decoder must never allocate more than the input justifies: a few bytes
// that CLAIM gigabytes must fail cheaply.
func TestCBORNoUnboundedAllocation(t *testing.T) {
	claims := [][]byte{
		{0x5b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x7b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		{0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 1000; i++ {
		for _, c := range claims {
			if _, err := DecodeCBOR(c); err == nil {
				t.Fatal("accepted")
			}
		}
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("decoder allocated %d bytes for tiny hostile inputs", grew)
	}
}

func FuzzCBOR(f *testing.F) {
	a := wt.New(AlgES256, rpID)
	_, obj := a.Create(chal(), origin)
	for _, seed := range [][]byte{obj, a.COSEKey(), {0xa1, 0x01, 0x02}, {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0x9f, 0xff}, {}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := DecodeCBOR(in)
		if err == nil && v == nil && len(in) != 1 { // only a bare null decodes to nil
			t.Fatalf("nil value from %x", in)
		}
		_, _, _ = DecodeCBORPrefix(in)
		_, _ = ParseCOSEKey(in)
		_, _ = ParseAuthData(in)
	})
}

func FuzzVerify(f *testing.F) {
	a := wt.New(AlgES256, rpID)
	cd, obj := a.Create(chal(), origin)
	f.Add(cd, obj)
	f.Fuzz(func(t *testing.T, cd, obj []byte) {
		_, _ = VerifyRegistration(rp, chal(), cd, obj, true)
	})
}
