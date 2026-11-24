// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Shared Signals state (core.SSFStore). Kept beside the Store, keyed by its
// pointer. Rows remember the ID of the realm they were created in, so a
// deleted and re-created realm of the same name never sees old rows (the
// Postgres store uses ON DELETE CASCADE).

type ssfRecv struct {
	core.SSFReceiver
	realmID string
}

type ssfStrm struct {
	core.SSFStream
	realmID  string
	subjects map[string]time.Time
}

type ssfOut struct {
	core.SSFOutbox
	realmID string
	leased  time.Time
}

type ssfState struct {
	mu   sync.Mutex
	recv map[string]*ssfRecv // by receiver ID
	strm map[string]*ssfStrm // by stream ID
	out  []*ssfOut
}

var ssfStates sync.Map // *Store -> *ssfState

var _ core.SSFStore = (*Store)(nil)

func (s *Store) ssf() *ssfState {
	v, _ := ssfStates.LoadOrStore(s, &ssfState{recv: map[string]*ssfRecv{}, strm: map[string]*ssfStrm{}})
	return v.(*ssfState)
}

func (s *Store) liveRealmID(ctx context.Context, name string) (string, error) {
	r, err := s.GetRealm(ctx, name)
	return r.ID, err
}

// liveRealms maps realm ID to name for every realm that exists now.
func (s *Store) liveRealms(ctx context.Context) map[string]string {
	out := map[string]string{}
	rs, _ := s.ListRealms(ctx)
	for _, r := range rs {
		out[r.ID] = r.Name
	}
	return out
}

func cloneRecv(r core.SSFReceiver) core.SSFReceiver {
	r.Events = slices.Clone(r.Events)
	return r
}

func cloneStrm(s core.SSFStream) core.SSFStream {
	s.EventsRequested = slices.Clone(s.EventsRequested)
	s.EventsDelivered = slices.Clone(s.EventsDelivered)
	return s
}

func (s *Store) CreateSSFReceiver(ctx context.Context, r core.SSFReceiver) (core.SSFReceiver, error) {
	rid, err := s.liveRealmID(ctx, r.Realm)
	if err != nil {
		return core.SSFReceiver{}, err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, x := range st.recv {
		if x.TokenHash == r.TokenHash || (x.realmID == rid && strings.EqualFold(x.Name, r.Name)) {
			return core.SSFReceiver{}, idp.ErrConflict
		}
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	r.CreatedAt = r.CreatedAt.UTC()
	st.recv[r.ID] = &ssfRecv{SSFReceiver: cloneRecv(r), realmID: rid}
	return cloneRecv(r), nil
}

func (s *Store) ssfRecvLocked(st *ssfState, rid, id string) (*ssfRecv, error) {
	r, ok := st.recv[id]
	if !ok || r.realmID != rid {
		return nil, idp.ErrNotFound
	}
	return r, nil
}

func (s *Store) GetSSFReceiver(ctx context.Context, realm, id string) (core.SSFReceiver, error) {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return core.SSFReceiver{}, err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, err := s.ssfRecvLocked(st, rid, id)
	if err != nil {
		return core.SSFReceiver{}, err
	}
	return cloneRecv(r.SSFReceiver), nil
}

func (s *Store) GetSSFReceiverByTokenHash(ctx context.Context, tokenHash string) (core.SSFReceiver, error) {
	live := s.liveRealms(ctx)
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	if tokenHash == "" {
		return core.SSFReceiver{}, idp.ErrNotFound
	}
	for _, r := range st.recv {
		if r.TokenHash == tokenHash {
			if live[r.realmID] != r.Realm {
				return core.SSFReceiver{}, idp.ErrNotFound
			}
			return cloneRecv(r.SSFReceiver), nil
		}
	}
	return core.SSFReceiver{}, idp.ErrNotFound
}

func (s *Store) ListSSFReceivers(ctx context.Context, realm string) ([]core.SSFReceiver, error) {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []core.SSFReceiver{}
	for _, r := range st.recv {
		if r.realmID == rid {
			out = append(out, cloneRecv(r.SSFReceiver))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetSSFReceiverToken(ctx context.Context, realm, id, tokenHash string) error {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, err := s.ssfRecvLocked(st, rid, id)
	if err != nil {
		return err
	}
	for _, x := range st.recv {
		if x != r && x.TokenHash == tokenHash {
			return idp.ErrConflict
		}
	}
	r.TokenHash = tokenHash
	return nil
}

func (s *Store) SetSSFReceiverDisabled(ctx context.Context, realm, id string, disabled bool) error {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, err := s.ssfRecvLocked(st, rid, id)
	if err != nil {
		return err
	}
	r.Disabled = disabled
	return nil
}

func (s *Store) DeleteSSFReceiver(ctx context.Context, realm, id string) error {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, err := s.ssfRecvLocked(st, rid, id); err != nil {
		return err
	}
	delete(st.recv, id)
	for sid, x := range st.strm {
		if x.ReceiverID == id {
			delete(st.strm, sid)
		}
	}
	st.out = slices.DeleteFunc(st.out, func(o *ssfOut) bool { _, ok := st.strm[o.StreamID]; return !ok })
	return nil
}

// view builds the returned stream including the receiver-derived fields.
func (st *ssfState) view(x *ssfStrm) core.SSFStream {
	v := cloneStrm(x.SSFStream)
	if r, ok := st.recv[x.ReceiverID]; ok {
		v.Audience, v.AllSubjects, v.ReceiverOff = r.Audience, r.AllSubjects, r.Disabled
	}
	return v
}

func (s *Store) CreateSSFStream(ctx context.Context, in core.SSFStream, maxStreams int) (core.SSFStream, error) {
	rid, err := s.liveRealmID(ctx, in.Realm)
	if err != nil {
		return core.SSFStream{}, err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, err := s.ssfRecvLocked(st, rid, in.ReceiverID); err != nil {
		return core.SSFStream{}, err
	}
	n := 0
	for _, x := range st.strm {
		if x.ReceiverID == in.ReceiverID {
			n++
		}
	}
	if maxStreams > 0 && n >= maxStreams {
		return core.SSFStream{}, core.ErrSSFStreamLimit
	}
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	in.CreatedAt, in.UpdatedAt = in.CreatedAt.UTC(), in.UpdatedAt.UTC()
	x := &ssfStrm{SSFStream: cloneStrm(in), realmID: rid, subjects: map[string]time.Time{}}
	st.strm[in.ID] = x
	return st.view(x), nil
}

func (s *Store) ssfStrmLocked(st *ssfState, rid, id string) (*ssfStrm, error) {
	x, ok := st.strm[id]
	if !ok || x.realmID != rid {
		return nil, idp.ErrNotFound
	}
	return x, nil
}

func (s *Store) GetSSFStream(ctx context.Context, realm, id string) (core.SSFStream, error) {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return core.SSFStream{}, err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	x, err := s.ssfStrmLocked(st, rid, id)
	if err != nil {
		return core.SSFStream{}, err
	}
	return st.view(x), nil
}

func (s *Store) ListSSFStreams(ctx context.Context, realm, receiverID string) ([]core.SSFStream, error) {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []core.SSFStream{}
	for _, x := range st.strm {
		if x.realmID == rid && (receiverID == "" || x.ReceiverID == receiverID) {
			out = append(out, st.view(x))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *Store) UpdateSSFStream(ctx context.Context, in core.SSFStream) error {
	rid, err := s.liveRealmID(ctx, in.Realm)
	if err != nil {
		return err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	x, err := s.ssfStrmLocked(st, rid, in.ID)
	if err != nil {
		return err
	}
	in.ReceiverID, in.CreatedAt = x.ReceiverID, x.CreatedAt // immutable
	x.SSFStream = cloneStrm(in)
	x.UpdatedAt = in.UpdatedAt.UTC()
	return nil
}

func (s *Store) DeleteSSFStream(ctx context.Context, realm, id string) error {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, err := s.ssfStrmLocked(st, rid, id); err != nil {
		return err
	}
	delete(st.strm, id)
	st.out = slices.DeleteFunc(st.out, func(o *ssfOut) bool { return o.StreamID == id })
	return nil
}

func (s *Store) AddSSFSubject(ctx context.Context, realm, streamID, userID string, now time.Time) error {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	x, err := s.ssfStrmLocked(st, rid, streamID)
	if err != nil {
		return err
	}
	if _, ok := x.subjects[userID]; !ok {
		x.subjects[userID] = now.UTC()
	}
	return nil
}

func (s *Store) RemoveSSFSubject(ctx context.Context, realm, streamID, userID string) error {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	x, err := s.ssfStrmLocked(st, rid, streamID)
	if err != nil {
		return err
	}
	delete(x.subjects, userID)
	return nil
}

func (s *Store) SSFStreamsFor(ctx context.Context, realm, userID string) ([]core.SSFStream, error) {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	out := []core.SSFStream{}
	if userID == "" {
		return out, nil
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, x := range st.strm {
		if x.realmID != rid || x.Status == core.SSFStatusDisabled {
			continue
		}
		v := st.view(x)
		if v.ReceiverOff {
			continue
		}
		if _, member := x.subjects[userID]; v.AllSubjects || member {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) EnqueueSSF(ctx context.Context, items []core.SSFOutbox) error {
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, it := range items {
		x, ok := st.strm[it.StreamID]
		if !ok {
			return idp.ErrNotFound
		}
		if it.ID == "" {
			it.ID = uuid.NewString()
		}
		it.State = core.SSFOutboxPending
		it.NextAttempt, it.CreatedAt = it.NextAttempt.UTC(), it.CreatedAt.UTC()
		st.out = append(st.out, &ssfOut{SSFOutbox: it, realmID: x.realmID})
	}
	return nil
}

func (s *Store) ClaimSSFOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]core.SSFOutbox, error) {
	live := s.liveRealms(ctx)
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []core.SSFOutbox
	for _, o := range st.out {
		if len(out) >= limit {
			break
		}
		if o.State != core.SSFOutboxPending || o.NextAttempt.After(now) || o.leased.After(now) {
			continue
		}
		x, ok := st.strm[o.StreamID]
		if !ok || live[x.realmID] == "" || x.Status != core.SSFStatusEnabled || st.view(x).ReceiverOff {
			continue
		}
		o.leased = now.Add(lease)
		out = append(out, o.SSFOutbox)
	}
	return out, nil
}

func (s *Store) FinishSSFOutbox(_ context.Context, id, state string, next time.Time, outcome string) error {
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, o := range st.out {
		if o.ID == id {
			o.Attempts++
			o.State, o.LastOutcome, o.leased = state, outcome, time.Time{}
			if state == core.SSFOutboxPending {
				o.NextAttempt = next.UTC()
			}
			return nil
		}
	}
	return idp.ErrNotFound
}

func (s *Store) CountSSFOutbox(ctx context.Context, realm string) (map[string]int, error) {
	rid, err := s.liveRealmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := map[string]int{}
	for _, o := range st.out {
		if o.realmID == rid {
			out[o.State]++
		}
	}
	return out, nil
}

func (s *Store) PruneSSFOutbox(_ context.Context, delivered, dead, pending time.Time) (int, error) {
	st := s.ssf()
	st.mu.Lock()
	defer st.mu.Unlock()
	n := len(st.out)
	st.out = slices.DeleteFunc(st.out, func(o *ssfOut) bool {
		switch o.State {
		case core.SSFOutboxDelivered:
			return o.CreatedAt.Before(delivered)
		case core.SSFOutboxDead:
			return o.CreatedAt.Before(dead)
		default:
			return o.CreatedAt.Before(pending)
		}
	})
	return n - len(st.out), nil
}
