// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"context"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// PingStore is the readiness probe: ListRealms with a 2s timeout.
func PingStore(ctx context.Context, st core.Store) ([]core.Realm, time.Duration, error) {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	t := time.Now()
	rs, err := st.ListRealms(c)
	return rs, time.Since(t), err
}

// WatchStore samples the store every interval until ctx ends: ping result,
// ping duration and the age of each realm's newest active signing key. Series
// of realms that no longer exist are deleted. It samples once immediately.
func WatchStore(ctx context.Context, st core.Store, o *Observer, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	seen := map[string]bool{}
	sample := func() {
		rs, d, err := PingStore(ctx, st)
		o.SetStoreUp(err == nil, d)
		if err != nil {
			return
		}
		now := time.Now()
		cur := map[string]bool{}
		for _, r := range rs {
			l := realmLabel(r.Name)
			cur[l] = true
			keys, kerr := st.ListSigningKeys(ctx, r.Name)
			if kerr != nil {
				continue
			}
			var newest time.Time
			for _, k := range keys {
				if k.Active && k.CreatedAt.After(newest) {
					newest = k.CreatedAt
				}
			}
			if newest.IsZero() {
				o.keyAge.DeleteLabelValues(l)
				continue
			}
			o.keyAge.WithLabelValues(l).Set(now.Sub(newest).Seconds())
		}
		for l := range seen {
			if !cur[l] {
				o.keyAge.DeleteLabelValues(l)
			}
		}
		seen = cur
	}
	sample()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sample()
		}
	}
}

type auditStore struct {
	core.Store
	sink AuditSink
}

// AuditStore returns st with AppendEvent also emitting to sink. A nil sink
// returns st unchanged.
func AuditStore(st core.Store, sink AuditSink) core.Store {
	if sink == nil {
		return st
	}
	return &auditStore{Store: st, sink: sink}
}

func (a *auditStore) AppendEvent(ctx context.Context, e core.Event) error {
	err := a.Store.AppendEvent(ctx, e)
	sev := SeverityInfo
	if strings.HasSuffix(e.Type, "_ERROR") {
		sev = SeverityWarning
	}
	t := e.Time
	if t.IsZero() {
		t = time.Now().UTC()
	}
	a.sink.Emit(AuditEvent{
		Time: t, Realm: e.Realm, Type: e.Type, Severity: sev, UserID: e.UserID,
		ClientID: e.ClientID, IP: e.IP, Detail: e.Detail, RequestID: RequestID(ctx),
	})
	return err
}
