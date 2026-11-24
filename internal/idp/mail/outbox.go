// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"context"
	"strings"
	"sync"
)

// Outbox is a bounded in-memory Sender for tests and development.
type Outbox struct {
	mu   sync.Mutex
	max  int
	msgs []Message // oldest first
}

// NewOutbox returns an Outbox keeping at most max messages (default 100).
func NewOutbox(max int) *Outbox {
	if max <= 0 {
		max = 100
	}
	return &Outbox{max: max}
}

// Send records m, evicting the oldest message when full.
func (o *Outbox) Send(_ context.Context, m Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.max <= 0 {
		o.max = 100
	}
	if len(o.msgs) >= o.max {
		copy(o.msgs, o.msgs[1:])
		o.msgs = o.msgs[:len(o.msgs)-1]
	}
	o.msgs = append(o.msgs, m)
	return nil
}

// Messages returns the recorded messages, newest first.
func (o *Outbox) Messages() []Message {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]Message, len(o.msgs))
	for i, m := range o.msgs {
		out[len(o.msgs)-1-i] = m
	}
	return out
}

// Last returns the newest message sent to the given address.
func (o *Outbox) Last(to string) (Message, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := len(o.msgs) - 1; i >= 0; i-- {
		if strings.EqualFold(o.msgs[i].To, to) {
			return o.msgs[i], true
		}
	}
	return Message{}, false
}

// Clear drops all recorded messages.
func (o *Outbox) Clear() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.msgs = nil
}
