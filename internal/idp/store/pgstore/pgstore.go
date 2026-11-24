// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package pgstore is the PostgreSQL core.Store. Schema migrations are
// embedded and applied by Open.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Store is a core.Store backed by a pgx pool.
type Store struct {
	pool *pgxpool.Pool
}

var _ core.Store = (*Store)(nil)

// Open connects, runs pending migrations and returns the Store. The DSN is
// never included in returned errors beyond what pgx itself reports.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: connect: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// mapErr translates pg errors to the idp sentinels.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w", idp.ErrNotFound)
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%s: %w", pe.ConstraintName, idp.ErrConflict)
		case "23503": // missing parent realm
			return fmt.Errorf("%s: %w", pe.ConstraintName, idp.ErrNotFound)
		}
	}
	return err
}

// exec runs a write that must affect exactly one row, else ErrNotFound.
func (s *Store) exec1(ctx context.Context, sql string, args ...any) error {
	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return idp.ErrNotFound
	}
	return nil
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// arr makes a non-nil slice so pgx sends '{}' rather than NULL.
func arr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func utc(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func fromNull(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func nilBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// Realms

const realmCols = `name, id, display_name, enabled, self_registration, email_verification_required,
	brute_force_protection, transport_security, password_policy, access_token_ttl_ns,
	refresh_token_ttl_ns, session_idle_ttl_ns, auth_events_logged, admin_events_logged,
	refresh_token_rotation, created_at`

func scanRealm(row pgx.Row) (core.Realm, error) {
	var r core.Realm
	var at, rt, si int64
	err := row.Scan(&r.Name, &r.ID, &r.DisplayName, &r.Enabled, &r.SelfRegistration,
		&r.EmailVerificationRequired, &r.BruteForceProtection, &r.TransportSecurity,
		&r.PasswordPolicy, &at, &rt, &si, &r.AuthEventsLogged, &r.AdminEventsLogged,
		&r.RefreshTokenRotation, &r.CreatedAt)
	r.AccessTokenTTL, r.RefreshTokenTTL, r.SessionIdleTTL = time.Duration(at), time.Duration(rt), time.Duration(si)
	r.CreatedAt = utc(r.CreatedAt)
	return r, mapErr(err)
}

func (s *Store) CreateRealm(ctx context.Context, r core.Realm) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO realms (`+realmCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		r.Name, r.ID, r.DisplayName, r.Enabled, r.SelfRegistration, r.EmailVerificationRequired,
		r.BruteForceProtection, r.TransportSecurity, r.PasswordPolicy, int64(r.AccessTokenTTL),
		int64(r.RefreshTokenTTL), int64(r.SessionIdleTTL), r.AuthEventsLogged, r.AdminEventsLogged,
		r.RefreshTokenRotation, r.CreatedAt)
	return mapErr(err)
}

func (s *Store) GetRealm(ctx context.Context, name string) (core.Realm, error) {
	return scanRealm(s.pool.QueryRow(ctx, `SELECT `+realmCols+` FROM realms WHERE lower(name)=lower($1)`, name))
}

func (s *Store) ListRealms(ctx context.Context) ([]core.Realm, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+realmCols+` FROM realms ORDER BY name`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.Realm{}
	for rows.Next() {
		r, err := scanRealm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

// UpdateRealm replaces every field except ID, Name and CreatedAt.
func (s *Store) UpdateRealm(ctx context.Context, r core.Realm) error {
	return s.exec1(ctx, `UPDATE realms SET display_name=$2, enabled=$3, self_registration=$4,
		email_verification_required=$5, brute_force_protection=$6, transport_security=$7,
		password_policy=$8, access_token_ttl_ns=$9, refresh_token_ttl_ns=$10, session_idle_ttl_ns=$11,
		auth_events_logged=$12, admin_events_logged=$13, refresh_token_rotation=$14
		WHERE lower(name)=lower($1)`,
		r.Name, r.DisplayName, r.Enabled, r.SelfRegistration, r.EmailVerificationRequired,
		r.BruteForceProtection, r.TransportSecurity, r.PasswordPolicy, int64(r.AccessTokenTTL),
		int64(r.RefreshTokenTTL), int64(r.SessionIdleTTL), r.AuthEventsLogged, r.AdminEventsLogged,
		r.RefreshTokenRotation)
}

func (s *Store) DeleteRealm(ctx context.Context, name string) error {
	return s.exec1(ctx, `DELETE FROM realms WHERE lower(name)=lower($1)`, name)
}

// Users

const userCols = `id, realm, username, email, first_name, last_name, enabled, email_verified,
	pending_actions, password_hash, roles, groups, failed_logins, locked_until, created_at`

func scanUser(row pgx.Row) (core.User, error) {
	var u core.User
	var locked *time.Time
	err := row.Scan(&u.ID, &u.Realm, &u.Username, &u.Email, &u.FirstName, &u.LastName, &u.Enabled,
		&u.EmailVerified, &u.PendingActions, &u.PasswordHash, &u.Roles, &u.Groups, &u.FailedLogins,
		&locked, &u.CreatedAt)
	u.PendingActions, u.Roles, u.Groups = nilIfEmpty(u.PendingActions), nilIfEmpty(u.Roles), nilIfEmpty(u.Groups)
	u.LockedUntil, u.CreatedAt = fromNull(locked), utc(u.CreatedAt)
	return u, mapErr(err)
}

func (s *Store) CreateUser(ctx context.Context, u core.User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO users (`+userCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		u.ID, u.Realm, u.Username, u.Email, u.FirstName, u.LastName, u.Enabled, u.EmailVerified,
		arr(u.PendingActions), u.PasswordHash, arr(u.Roles), arr(u.Groups), u.FailedLogins,
		nullTime(u.LockedUntil), u.CreatedAt)
	return mapErr(err)
}

func (s *Store) GetUser(ctx context.Context, realm, id string) (core.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE realm=$1 AND id=$2`, realm, id))
}

func (s *Store) GetUserByUsername(ctx context.Context, realm, username string) (core.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE realm=$1 AND lower(username)=lower($2)`, realm, username))
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// ListUsers orders by username; search is a case-insensitive substring match
// on username, email and names. limit <= 0 means no limit.
func (s *Store) ListUsers(ctx context.Context, realm, search string, offset, limit int) ([]core.User, error) {
	if offset < 0 {
		offset = 0
	}
	var lim *int
	if limit > 0 {
		lim = &limit
	}
	pat := "%" + likeEscaper.Replace(search) + "%"
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users
		WHERE realm=$1 AND ($2 = '' OR username ILIKE $3 OR email ILIKE $3 OR first_name ILIKE $3 OR last_name ILIKE $3)
		ORDER BY lower(username), id OFFSET $4 LIMIT $5`, realm, search, pat, offset, lim)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, mapErr(rows.Err())
}

// UpdateUser replaces every field except ID, Realm and CreatedAt.
func (s *Store) UpdateUser(ctx context.Context, u core.User) error {
	return s.exec1(ctx, `UPDATE users SET username=$3, email=$4, first_name=$5, last_name=$6, enabled=$7,
		email_verified=$8, pending_actions=$9, password_hash=$10, roles=$11, groups=$12,
		failed_logins=$13, locked_until=$14 WHERE realm=$1 AND id=$2`,
		u.Realm, u.ID, u.Username, u.Email, u.FirstName, u.LastName, u.Enabled, u.EmailVerified,
		arr(u.PendingActions), u.PasswordHash, arr(u.Roles), arr(u.Groups), u.FailedLogins,
		nullTime(u.LockedUntil))
}

func (s *Store) DeleteUser(ctx context.Context, realm, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM users WHERE realm=$1 AND id=$2`, realm, id)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return idp.ErrNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE realm=$1 AND user_id=$2`, realm, id)
		return mapErr(err)
	})
}

// Clients

const clientCols = `id, realm, client_id, name, enabled, public, secret_hash, redirect_uris, origins,
	auth_code_flow, password_flow, service_account, require_pkce, created_at`

func scanClient(row pgx.Row) (core.Client, error) {
	var c core.Client
	err := row.Scan(&c.ID, &c.Realm, &c.ClientID, &c.Name, &c.Enabled, &c.Public, &c.SecretHash,
		&c.RedirectURIs, &c.Origins, &c.AuthCodeFlow, &c.PasswordFlow, &c.ServiceAccount,
		&c.RequirePKCE, &c.CreatedAt)
	c.RedirectURIs, c.Origins = nilIfEmpty(c.RedirectURIs), nilIfEmpty(c.Origins)
	c.CreatedAt = utc(c.CreatedAt)
	return c, mapErr(err)
}

func (s *Store) CreateClient(ctx context.Context, c core.Client) error {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO clients (`+clientCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		c.ID, c.Realm, c.ClientID, c.Name, c.Enabled, c.Public, c.SecretHash, arr(c.RedirectURIs),
		arr(c.Origins), c.AuthCodeFlow, c.PasswordFlow, c.ServiceAccount, c.RequirePKCE, c.CreatedAt)
	return mapErr(err)
}

func (s *Store) GetClient(ctx context.Context, realm, id string) (core.Client, error) {
	return scanClient(s.pool.QueryRow(ctx, `SELECT `+clientCols+` FROM clients WHERE realm=$1 AND id=$2`, realm, id))
}

func (s *Store) GetClientByClientID(ctx context.Context, realm, clientID string) (core.Client, error) {
	return scanClient(s.pool.QueryRow(ctx,
		`SELECT `+clientCols+` FROM clients WHERE realm=$1 AND client_id=$2`, realm, clientID))
}

func (s *Store) ListClients(ctx context.Context, realm string) ([]core.Client, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+clientCols+` FROM clients WHERE realm=$1 ORDER BY client_id`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, mapErr(rows.Err())
}

// UpdateClient replaces every field except ID, Realm and CreatedAt.
func (s *Store) UpdateClient(ctx context.Context, c core.Client) error {
	return s.exec1(ctx, `UPDATE clients SET client_id=$3, name=$4, enabled=$5, public=$6, secret_hash=$7,
		redirect_uris=$8, origins=$9, auth_code_flow=$10, password_flow=$11, service_account=$12,
		require_pkce=$13 WHERE realm=$1 AND id=$2`,
		c.Realm, c.ID, c.ClientID, c.Name, c.Enabled, c.Public, c.SecretHash, arr(c.RedirectURIs),
		arr(c.Origins), c.AuthCodeFlow, c.PasswordFlow, c.ServiceAccount, c.RequirePKCE)
}

func (s *Store) DeleteClient(ctx context.Context, realm, id string) error {
	return s.exec1(ctx, `DELETE FROM clients WHERE realm=$1 AND id=$2`, realm, id)
}

// Roles and groups

func (s *Store) CreateRole(ctx context.Context, r core.Role) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO roles (id, realm, name, description) VALUES ($1,$2,$3,$4)`,
		r.ID, r.Realm, r.Name, r.Description)
	return mapErr(err)
}

func (s *Store) ListRoles(ctx context.Context, realm string) ([]core.Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, realm, name, description FROM roles WHERE realm=$1 ORDER BY name`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.Role{}
	for rows.Next() {
		var r core.Role
		if err := rows.Scan(&r.ID, &r.Realm, &r.Name, &r.Description); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) CreateGroup(ctx context.Context, g core.Group) error {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO groups (id, realm, name, path) VALUES ($1,$2,$3,$4)`,
		g.ID, g.Realm, g.Name, g.Path)
	return mapErr(err)
}

func (s *Store) ListGroups(ctx context.Context, realm string) ([]core.Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, realm, name, path FROM groups WHERE realm=$1 ORDER BY path`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.Group{}
	for rows.Next() {
		var g core.Group
		if err := rows.Scan(&g.ID, &g.Realm, &g.Name, &g.Path); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, g)
	}
	return out, mapErr(rows.Err())
}

// Signing keys

// PutSigningKey inserts or replaces the key identified by (realm, KID).
func (s *Store) PutSigningKey(ctx context.Context, k core.SigningKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	priv, pub := k.PrivatePEM, k.PublicJWK
	if priv == nil {
		priv = []byte{}
	}
	if pub == nil {
		pub = []byte{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO signing_keys (realm, kid, alg, private_pem, public_jwk, active, not_after, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (realm, kid) DO UPDATE SET alg=EXCLUDED.alg, private_pem=EXCLUDED.private_pem,
			public_jwk=EXCLUDED.public_jwk, active=EXCLUDED.active, not_after=EXCLUDED.not_after,
			created_at=EXCLUDED.created_at`,
		k.Realm, k.KID, k.Alg, priv, pub, k.Active, nullTime(k.NotAfter), k.CreatedAt)
	return mapErr(err)
}

// ListSigningKeys returns active keys first, then newest first.
func (s *Store) ListSigningKeys(ctx context.Context, realm string) ([]core.SigningKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT kid, realm, alg, private_pem, public_jwk, active, not_after, created_at
		FROM signing_keys WHERE realm=$1 ORDER BY active DESC, created_at DESC, kid`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.SigningKey{}
	for rows.Next() {
		var k core.SigningKey
		var na *time.Time
		if err := rows.Scan(&k.KID, &k.Realm, &k.Alg, &k.PrivatePEM, &k.PublicJWK, &k.Active, &na, &k.CreatedAt); err != nil {
			return nil, mapErr(err)
		}
		k.PrivatePEM, k.PublicJWK = nilBytes(k.PrivatePEM), nilBytes(k.PublicJWK)
		k.NotAfter, k.CreatedAt = fromNull(na), utc(k.CreatedAt)
		out = append(out, k)
	}
	return out, mapErr(rows.Err())
}

// Authorization codes

const codeCols = `code_hash, realm, client_id, user_id, redirect_uri, scope, nonce, code_challenge,
	challenge_meth, auth_time, session_id, expires_at`

func (s *Store) PutAuthCode(ctx context.Context, c core.AuthCode) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO auth_codes (`+codeCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		c.CodeHash, c.Realm, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.Nonce, c.CodeChallenge,
		c.ChallengeMeth, c.AuthTime, c.SessionID, c.ExpiresAt)
	return mapErr(err)
}

// ConsumeAuthCode is a single DELETE ... RETURNING, so exactly one caller wins.
func (s *Store) ConsumeAuthCode(ctx context.Context, codeHash string) (core.AuthCode, error) {
	var c core.AuthCode
	err := s.pool.QueryRow(ctx, `DELETE FROM auth_codes WHERE code_hash=$1 RETURNING `+codeCols, codeHash).
		Scan(&c.CodeHash, &c.Realm, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce,
			&c.CodeChallenge, &c.ChallengeMeth, &c.AuthTime, &c.SessionID, &c.ExpiresAt)
	c.AuthTime, c.ExpiresAt = utc(c.AuthTime), utc(c.ExpiresAt)
	return c, mapErr(err)
}

// Refresh tokens

func (s *Store) PutRefreshToken(ctx context.Context, t core.RefreshToken) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO refresh_tokens
		(token_hash, family_id, realm, client_id, user_id, session_id, scope, used, revoked, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		t.TokenHash, t.FamilyID, t.Realm, t.ClientID, t.UserID, t.SessionID, t.Scope, t.Used, t.Revoked, t.ExpiresAt, t.CreatedAt)
	return mapErr(err)
}

func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (core.RefreshToken, error) {
	var t core.RefreshToken
	err := s.pool.QueryRow(ctx, `SELECT token_hash, family_id, realm, client_id, user_id, session_id, scope, used,
		revoked, expires_at, created_at FROM refresh_tokens WHERE token_hash=$1`, tokenHash).
		Scan(&t.TokenHash, &t.FamilyID, &t.Realm, &t.ClientID, &t.UserID, &t.SessionID, &t.Scope, &t.Used,
			&t.Revoked, &t.ExpiresAt, &t.CreatedAt)
	t.ExpiresAt, t.CreatedAt = utc(t.ExpiresAt), utc(t.CreatedAt)
	return t, mapErr(err)
}

// MarkRefreshUsed flips used false->true atomically; a second call gets
// idp.ErrConflict, an unknown token idp.ErrNotFound.
func (s *Store) MarkRefreshUsed(ctx context.Context, tokenHash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET used=true WHERE token_hash=$1 AND used=false`, tokenHash)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var one int
	err = s.pool.QueryRow(ctx, `SELECT 1 FROM refresh_tokens WHERE token_hash=$1`, tokenHash).Scan(&one)
	if err != nil {
		return mapErr(err)
	}
	return fmt.Errorf("refresh token already used: %w", idp.ErrConflict)
}

func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked=true WHERE family_id=$1`, familyID)
	return mapErr(err)
}

// Events

func (s *Store) AppendEvent(ctx context.Context, e core.Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO events (realm, time, type, user_id, client_id, ip, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, e.Realm, e.Time, e.Type, e.UserID, e.ClientID, e.IP, e.Detail)
	return mapErr(err)
}

// ListEvents returns the newest events first; limit <= 0 means 100.
func (s *Store) ListEvents(ctx context.Context, realm string, limit int) ([]core.Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT time, realm, type, user_id, client_id, ip, detail FROM events
		WHERE realm=$1 ORDER BY time DESC, seq DESC LIMIT $2`, realm, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.Event{}
	for rows.Next() {
		var e core.Event
		if err := rows.Scan(&e.Time, &e.Realm, &e.Type, &e.UserID, &e.ClientID, &e.IP, &e.Detail); err != nil {
			return nil, mapErr(err)
		}
		e.Time = utc(e.Time)
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}

// RevokeUserRefreshTokens revokes every not-yet-revoked refresh token of the
// user and returns how many were newly revoked.
func (s *Store) RevokeUserRefreshTokens(ctx context.Context, realm, userID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked=true
		WHERE realm=$1 AND user_id=$2 AND NOT revoked`, realm, userID)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}

// Action tokens

func (s *Store) PutActionToken(ctx context.Context, t core.ActionToken) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO action_tokens
		(token_hash, realm, user_id, purpose, email, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		t.TokenHash, t.Realm, t.UserID, t.Purpose, t.Email, t.CreatedAt, t.ExpiresAt)
	return mapErr(err)
}

// ConsumeActionToken is a single DELETE ... RETURNING, so exactly one caller wins.
func (s *Store) ConsumeActionToken(ctx context.Context, tokenHash string) (core.ActionToken, error) {
	var t core.ActionToken
	err := s.pool.QueryRow(ctx, `DELETE FROM action_tokens WHERE token_hash=$1
		RETURNING token_hash, realm, user_id, purpose, email, created_at, expires_at`, tokenHash).
		Scan(&t.TokenHash, &t.Realm, &t.UserID, &t.Purpose, &t.Email, &t.CreatedAt, &t.ExpiresAt)
	t.CreatedAt, t.ExpiresAt = utc(t.CreatedAt), utc(t.ExpiresAt)
	return t, mapErr(err)
}

func (s *Store) DeleteActionTokens(ctx context.Context, realm, userID, purpose string) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM action_tokens WHERE realm=$1 AND user_id=$2 AND purpose=$3`,
		realm, userID, purpose)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) CountActionTokens(ctx context.Context, realm, userID, purpose string, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM action_tokens
		WHERE realm=$1 AND user_id=$2 AND purpose=$3 AND created_at >= $4`,
		realm, userID, purpose, since).Scan(&n)
	return n, mapErr(err)
}

// HitRateLimit is one atomic upsert: a new key or an ended window starts a
// fresh window at now with count 1; otherwise count is incremented (capped at
// max+1 so denied hits do not grow it). No read-then-write race.
func (s *Store) HitRateLimit(ctx context.Context, key string, now time.Time, window time.Duration, max int) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `INSERT INTO rate_limits AS r (key, window_start, count, expires_at)
		VALUES ($1, $2, 1, $3)
		ON CONFLICT (key) DO UPDATE SET
			window_start = CASE WHEN r.expires_at <= $2 THEN $2 ELSE r.window_start END,
			expires_at   = CASE WHEN r.expires_at <= $2 THEN $3 ELSE r.expires_at END,
			count        = CASE WHEN r.expires_at <= $2 THEN 1 ELSE LEAST(r.count + 1, $4::int + 1) END
		RETURNING count`, key, now, now.Add(window), max).Scan(&n)
	if err != nil {
		return false, mapErr(err)
	}
	return n <= max, nil
}

// PurgeExpired deletes auth codes, refresh tokens, action tokens, ended SSO
// sessions (absolute or idle expiry) and rate-limit windows that expired at or before now.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `WITH c AS (DELETE FROM auth_codes WHERE expires_at <= $1 RETURNING 1),
		t AS (DELETE FROM refresh_tokens WHERE expires_at <= $1 RETURNING 1),
		a AS (DELETE FROM action_tokens WHERE expires_at <= $1 RETURNING 1),
		l AS (DELETE FROM rate_limits WHERE expires_at <= $1 RETURNING 1),
		x AS (DELETE FROM sessions WHERE expires_at <= $1 OR idle_expires <= $1 RETURNING 1)
		SELECT (SELECT count(*) FROM c) + (SELECT count(*) FROM t) + (SELECT count(*) FROM a) + (SELECT count(*) FROM l) + (SELECT count(*) FROM x)`, now).Scan(&n)
	return n, mapErr(err)
}

// Sessions

const sessionCols = `id, cookie_hash, realm, user_id, auth_time, last_seen, idle_expires, expires_at,
	ip, user_agent, clients, created_at`

func scanSession(row pgx.Row) (core.Session, error) {
	var x core.Session
	err := row.Scan(&x.ID, &x.CookieHash, &x.Realm, &x.UserID, &x.AuthTime, &x.LastSeen, &x.IdleExpires,
		&x.ExpiresAt, &x.IP, &x.UserAgent, &x.Clients, &x.CreatedAt)
	x.Clients = nilIfEmpty(x.Clients)
	x.AuthTime, x.LastSeen, x.IdleExpires = utc(x.AuthTime), utc(x.LastSeen), utc(x.IdleExpires)
	x.ExpiresAt, x.CreatedAt = utc(x.ExpiresAt), utc(x.CreatedAt)
	return x, mapErr(err)
}

func collectSessions(rows pgx.Rows) ([]core.Session, error) {
	defer rows.Close()
	out := []core.Session{}
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) PutSession(ctx context.Context, x core.Session) error {
	if x.CreatedAt.IsZero() {
		x.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (`+sessionCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		x.ID, x.CookieHash, x.Realm, x.UserID, x.AuthTime, x.LastSeen, x.IdleExpires, x.ExpiresAt,
		x.IP, x.UserAgent, arr(x.Clients), x.CreatedAt)
	return mapErr(err)
}

func (s *Store) GetSession(ctx context.Context, realm, id string) (core.Session, error) {
	return scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE realm=$1 AND id=$2`, realm, id))
}

func (s *Store) GetSessionByCookie(ctx context.Context, realm, cookieHash string) (core.Session, error) {
	return scanSession(s.pool.QueryRow(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE realm=$1 AND cookie_hash=$2`, realm, cookieHash))
}

func (s *Store) TouchSession(ctx context.Context, realm, id string, lastSeen, idleExpires time.Time) error {
	return s.exec1(ctx, `UPDATE sessions SET last_seen=$3, idle_expires=$4 WHERE realm=$1 AND id=$2`,
		realm, id, lastSeen, idleExpires)
}

// AddSessionClient is one atomic UPDATE that appends only if absent, so
// concurrent callers neither duplicate nor lose a client.
func (s *Store) AddSessionClient(ctx context.Context, realm, id, clientID string) error {
	return s.exec1(ctx, `UPDATE sessions SET clients = CASE WHEN $3::text = ANY(clients) THEN clients
		ELSE array_append(clients, $3::text) END WHERE realm=$1 AND id=$2`, realm, id, clientID)
}

// ListSessions returns newest first; limit <= 0 means 100.
func (s *Store) ListSessions(ctx context.Context, realm, userID string, limit int) ([]core.Session, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+sessionCols+` FROM sessions
		WHERE realm=$1 AND ($2::text = '' OR user_id=$2) ORDER BY created_at DESC, id LIMIT $3`, realm, userID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	return collectSessions(rows)
}

// TakeSession is a single DELETE ... RETURNING, so exactly one caller wins.
func (s *Store) TakeSession(ctx context.Context, realm, id string) (core.Session, error) {
	return scanSession(s.pool.QueryRow(ctx,
		`DELETE FROM sessions WHERE realm=$1 AND id=$2 RETURNING `+sessionCols, realm, id))
}

func (s *Store) TakeUserSessions(ctx context.Context, realm, userID string) ([]core.Session, error) {
	rows, err := s.pool.Query(ctx, `DELETE FROM sessions WHERE realm=$1 AND user_id=$2 RETURNING `+sessionCols, realm, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	return collectSessions(rows)
}

// RevokeSessionRefreshTokens revokes the session's refresh tokens except
// those whose scope contains the whitespace-delimited word offline_access.
func (s *Store) RevokeSessionRefreshTokens(ctx context.Context, realm, sessionID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked=true
		WHERE realm=$1 AND session_id=$2 AND NOT revoked
		AND scope !~ '(^|\s)offline_access(\s|$)'`, realm, sessionID)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}
