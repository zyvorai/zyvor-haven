// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.SSFStore = (*Store)(nil)

const ssfRecvCols = `id, realm, name, audience, token_hash, all_subjects, allow_email, events, disabled, created_at`

func scanSSFRecv(row pgx.Row) (core.SSFReceiver, error) {
	var r core.SSFReceiver
	err := row.Scan(&r.ID, &r.Realm, &r.Name, &r.Audience, &r.TokenHash, &r.AllSubjects, &r.AllowEmail, &r.Events, &r.Disabled, &r.CreatedAt)
	r.CreatedAt = utc(r.CreatedAt)
	return r, mapErr(err)
}

func (s *Store) CreateSSFReceiver(ctx context.Context, r core.SSFReceiver) (core.SSFReceiver, error) {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	r.CreatedAt = r.CreatedAt.UTC()
	_, err := s.pool.Exec(ctx, `INSERT INTO ssf_receivers (`+ssfRecvCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		r.ID, r.Realm, r.Name, r.Audience, r.TokenHash, r.AllSubjects, r.AllowEmail, arr(r.Events), r.Disabled, r.CreatedAt)
	if err != nil {
		return core.SSFReceiver{}, mapErr(err)
	}
	return r, nil
}

func (s *Store) GetSSFReceiver(ctx context.Context, realm, id string) (core.SSFReceiver, error) {
	return scanSSFRecv(s.pool.QueryRow(ctx, `SELECT `+ssfRecvCols+` FROM ssf_receivers WHERE realm=$1 AND id=$2`, realm, id))
}

func (s *Store) GetSSFReceiverByTokenHash(ctx context.Context, tokenHash string) (core.SSFReceiver, error) {
	if tokenHash == "" {
		return core.SSFReceiver{}, idp.ErrNotFound
	}
	return scanSSFRecv(s.pool.QueryRow(ctx, `SELECT `+ssfRecvCols+` FROM ssf_receivers WHERE token_hash=$1`, tokenHash))
}

func (s *Store) ListSSFReceivers(ctx context.Context, realm string) ([]core.SSFReceiver, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ssfRecvCols+` FROM ssf_receivers WHERE realm=$1 ORDER BY name`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.SSFReceiver{}
	for rows.Next() {
		r, err := scanSSFRecv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) SetSSFReceiverToken(ctx context.Context, realm, id, tokenHash string) error {
	return s.exec1(ctx, `UPDATE ssf_receivers SET token_hash=$3 WHERE realm=$1 AND id=$2`, realm, id, tokenHash)
}

func (s *Store) SetSSFReceiverDisabled(ctx context.Context, realm, id string, disabled bool) error {
	return s.exec1(ctx, `UPDATE ssf_receivers SET disabled=$3 WHERE realm=$1 AND id=$2`, realm, id, disabled)
}

func (s *Store) DeleteSSFReceiver(ctx context.Context, realm, id string) error {
	return s.exec1(ctx, `DELETE FROM ssf_receivers WHERE realm=$1 AND id=$2`, realm, id)
}

// Stream columns joined with the receiver's read-only attributes.
const ssfStrmSel = `SELECT s.id, s.realm, s.receiver_id, r.audience, s.status, s.endpoint_url, s.sealed_auth,
    s.events_requested, s.events_delivered, s.description, s.subject_format, r.all_subjects, r.disabled, s.created_at, s.updated_at
    FROM ssf_streams s JOIN ssf_receivers r ON r.id = s.receiver_id `

func scanSSFStrm(row pgx.Row) (core.SSFStream, error) {
	var x core.SSFStream
	err := row.Scan(&x.ID, &x.Realm, &x.ReceiverID, &x.Audience, &x.Status, &x.EndpointURL, &x.SealedAuth,
		&x.EventsRequested, &x.EventsDelivered, &x.Description, &x.SubjectFormat, &x.AllSubjects, &x.ReceiverOff, &x.CreatedAt, &x.UpdatedAt)
	x.CreatedAt, x.UpdatedAt = utc(x.CreatedAt), utc(x.UpdatedAt)
	return x, mapErr(err)
}

func collectSSFStrm(rows pgx.Rows, err error) ([]core.SSFStream, error) {
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.SSFStream{}
	for rows.Next() {
		x, err := scanSSFStrm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, mapErr(rows.Err())
}

// CreateSSFStream counts and inserts under a per-receiver advisory lock so
// concurrent creates cannot exceed maxStreams.
func (s *Store) CreateSSFStream(ctx context.Context, in core.SSFStream, maxStreams int) (core.SSFStream, error) {
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	in.CreatedAt, in.UpdatedAt = in.CreatedAt.UTC(), in.UpdatedAt.UTC()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ssf_streams|' || $1, 0))`, in.ReceiverID); err != nil {
			return err
		}
		var okRecv bool
		if err := tx.QueryRow(ctx, `SELECT true FROM ssf_receivers WHERE realm=$1 AND id=$2`, in.Realm, in.ReceiverID).Scan(&okRecv); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ssf_streams WHERE receiver_id=$1`, in.ReceiverID).Scan(&n); err != nil {
			return err
		}
		if maxStreams > 0 && n >= maxStreams {
			return core.ErrSSFStreamLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO ssf_streams (id, realm, receiver_id, status, endpoint_url, sealed_auth,
			events_requested, events_delivered, description, subject_format, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			in.ID, in.Realm, in.ReceiverID, in.Status, in.EndpointURL, in.SealedAuth, arr(in.EventsRequested),
			arr(in.EventsDelivered), in.Description, in.SubjectFormat, in.CreatedAt, in.UpdatedAt)
		return err
	})
	if err != nil {
		if err == core.ErrSSFStreamLimit {
			return core.SSFStream{}, err
		}
		return core.SSFStream{}, mapErr(err)
	}
	return s.GetSSFStream(ctx, in.Realm, in.ID)
}

func (s *Store) GetSSFStream(ctx context.Context, realm, id string) (core.SSFStream, error) {
	return scanSSFStrm(s.pool.QueryRow(ctx, ssfStrmSel+`WHERE s.realm=$1 AND s.id=$2`, realm, id))
}

func (s *Store) ListSSFStreams(ctx context.Context, realm, receiverID string) ([]core.SSFStream, error) {
	if receiverID == "" {
		return collectSSFStrm(s.pool.Query(ctx, ssfStrmSel+`WHERE s.realm=$1 ORDER BY s.created_at, s.id`, realm))
	}
	return collectSSFStrm(s.pool.Query(ctx, ssfStrmSel+`WHERE s.realm=$1 AND s.receiver_id=$2 ORDER BY s.created_at, s.id`, realm, receiverID))
}

func (s *Store) UpdateSSFStream(ctx context.Context, in core.SSFStream) error {
	return s.exec1(ctx, `UPDATE ssf_streams SET status=$3, endpoint_url=$4, sealed_auth=$5, events_requested=$6,
		events_delivered=$7, description=$8, subject_format=$9, updated_at=$10 WHERE realm=$1 AND id=$2`,
		in.Realm, in.ID, in.Status, in.EndpointURL, in.SealedAuth, arr(in.EventsRequested), arr(in.EventsDelivered),
		in.Description, in.SubjectFormat, in.UpdatedAt.UTC())
}

func (s *Store) DeleteSSFStream(ctx context.Context, realm, id string) error {
	return s.exec1(ctx, `DELETE FROM ssf_streams WHERE realm=$1 AND id=$2`, realm, id)
}

func (s *Store) AddSSFSubject(ctx context.Context, realm, streamID, userID string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO ssf_subjects (stream_id, user_id, added_at)
		SELECT id, $3, $4 FROM ssf_streams WHERE realm=$1 AND id=$2
		ON CONFLICT (stream_id, user_id) DO NOTHING`, realm, streamID, userID, now.UTC())
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		// Either the stream is missing or the subject already exists.
		var ok bool
		if err := s.pool.QueryRow(ctx, `SELECT true FROM ssf_streams WHERE realm=$1 AND id=$2`, realm, streamID).Scan(&ok); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (s *Store) RemoveSSFSubject(ctx context.Context, realm, streamID, userID string) error {
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT true FROM ssf_streams WHERE realm=$1 AND id=$2`, realm, streamID).Scan(&ok); err != nil {
		return mapErr(err)
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM ssf_subjects WHERE stream_id=$1 AND user_id=$2`, streamID, userID)
	return mapErr(err)
}

func (s *Store) SSFStreamsFor(ctx context.Context, realm, userID string) ([]core.SSFStream, error) {
	if userID == "" {
		return []core.SSFStream{}, nil
	}
	return collectSSFStrm(s.pool.Query(ctx, ssfStrmSel+`WHERE s.realm=$1 AND s.status <> 'disabled' AND NOT r.disabled
		AND (r.all_subjects OR EXISTS (SELECT 1 FROM ssf_subjects j WHERE j.stream_id = s.id AND j.user_id = $2))
		ORDER BY s.id`, realm, userID))
}

func (s *Store) EnqueueSSF(ctx context.Context, items []core.SSFOutbox) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, it := range items {
			if it.ID == "" {
				it.ID = uuid.NewString()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ssf_outbox (id, realm, stream_id, jti, event_type, set_jwt, next_attempt, created_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				it.ID, it.Realm, it.StreamID, it.JTI, it.EventType, it.SET, it.NextAttempt.UTC(), it.CreatedAt.UTC()); err != nil {
				return mapErr(err)
			}
		}
		return nil
	})
}

func (s *Store) ClaimSSFOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]core.SSFOutbox, error) {
	rows, err := s.pool.Query(ctx, `UPDATE ssf_outbox o SET leased_until = $2 FROM (
		SELECT o2.id FROM ssf_outbox o2
		JOIN ssf_streams s ON s.id = o2.stream_id
		JOIN ssf_receivers r ON r.id = s.receiver_id
		WHERE o2.state='pending' AND o2.next_attempt <= $1 AND (o2.leased_until IS NULL OR o2.leased_until <= $1)
		  AND s.status='enabled' AND NOT r.disabled
		ORDER BY o2.next_attempt LIMIT $3 FOR UPDATE OF o2 SKIP LOCKED) pick
		WHERE o.id = pick.id
		RETURNING o.id, o.realm, o.stream_id, o.jti, o.event_type, o.set_jwt, o.attempts, o.next_attempt, o.created_at, o.state, o.last_outcome`,
		now.UTC(), now.Add(lease).UTC(), limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []core.SSFOutbox
	for rows.Next() {
		var o core.SSFOutbox
		if err := rows.Scan(&o.ID, &o.Realm, &o.StreamID, &o.JTI, &o.EventType, &o.SET, &o.Attempts, &o.NextAttempt, &o.CreatedAt, &o.State, &o.LastOutcome); err != nil {
			return nil, mapErr(err)
		}
		o.NextAttempt, o.CreatedAt = utc(o.NextAttempt), utc(o.CreatedAt)
		out = append(out, o)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) FinishSSFOutbox(ctx context.Context, id, state string, next time.Time, outcome string) error {
	if state == core.SSFOutboxPending {
		return s.exec1(ctx, `UPDATE ssf_outbox SET attempts=attempts+1, state=$2, last_outcome=$3, next_attempt=$4, leased_until=NULL WHERE id=$1`,
			id, state, outcome, next.UTC())
	}
	return s.exec1(ctx, `UPDATE ssf_outbox SET attempts=attempts+1, state=$2, last_outcome=$3, leased_until=NULL WHERE id=$1`, id, state, outcome)
}

func (s *Store) CountSSFOutbox(ctx context.Context, realm string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT state, count(*) FROM ssf_outbox WHERE realm=$1 GROUP BY state`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, mapErr(err)
		}
		out[st] = n
	}
	return out, mapErr(rows.Err())
}

func (s *Store) PruneSSFOutbox(ctx context.Context, delivered, dead, pending time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ssf_outbox WHERE
		(state='delivered' AND created_at < $1) OR (state='dead' AND created_at < $2) OR (state='pending' AND created_at < $3)`,
		delivered.UTC(), dead.UTC(), pending.UTC())
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}
