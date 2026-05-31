package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
	"github.com/krishnaditya65/Project-Janus/internal/webauthn/domain"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}

func (r *Repository) Create(ctx context.Context, c *domain.Credential) error {
	const q = `
		INSERT INTO webauthn_credentials
		(id, identity_id, credential_id, public_key, attestation, aaguid, sign_count, transports, user_handle, label, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	transports, _ := json.Marshal(c.Transports)
	_, err := r.executor(ctx).Exec(ctx, q,
		c.ID, c.IdentityID, c.CredentialID, c.PublicKey, c.Attestation, c.AAGUID,
		c.SignCount, transports, c.UserHandle, c.Label, c.CreatedAt)
	return err
}

func (r *Repository) GetByCredentialID(ctx context.Context, credID []byte) (*domain.Credential, error) {
	const q = `
		SELECT id, identity_id, credential_id, public_key, COALESCE(attestation, ''), aaguid,
			sign_count, COALESCE(transports, '[]'::jsonb), user_handle, COALESCE(label, ''),
			created_at, last_used_at
		FROM webauthn_credentials WHERE credential_id = $1`
	return r.scanOne(ctx, q, credID)
}

func (r *Repository) ListByIdentity(ctx context.Context, identityID string) ([]*domain.Credential, error) {
	return r.list(ctx, `
		SELECT id, identity_id, credential_id, public_key, COALESCE(attestation, ''), aaguid,
			sign_count, COALESCE(transports, '[]'::jsonb), user_handle, COALESCE(label, ''),
			created_at, last_used_at
		FROM webauthn_credentials WHERE identity_id = $1`, identityID)
}

func (r *Repository) ListByUserHandle(ctx context.Context, handle []byte) ([]*domain.Credential, error) {
	return r.list(ctx, `
		SELECT id, identity_id, credential_id, public_key, COALESCE(attestation, ''), aaguid,
			sign_count, COALESCE(transports, '[]'::jsonb), user_handle, COALESCE(label, ''),
			created_at, last_used_at
		FROM webauthn_credentials WHERE user_handle = $1`, handle)
}

func (r *Repository) UpdateSignCount(ctx context.Context, id string, count uint32) error {
	_, err := r.executor(ctx).Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count = $1, last_used_at = NOW() WHERE id = $2`, count, id)
	return err
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	_, err := r.executor(ctx).Exec(ctx, `DELETE FROM webauthn_credentials WHERE id = $1`, id)
	return err
}

func (r *Repository) scanOne(ctx context.Context, q string, args ...any) (*domain.Credential, error) {
	row := r.executor(ctx).QueryRow(ctx, q, args...)
	c := &domain.Credential{}
	var transports []byte
	err := row.Scan(&c.ID, &c.IdentityID, &c.CredentialID, &c.PublicKey, &c.Attestation, &c.AAGUID,
		&c.SignCount, &transports, &c.UserHandle, &c.Label, &c.CreatedAt, &c.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(transports, &c.Transports)
	return c, nil
}

func (r *Repository) list(ctx context.Context, q string, args ...any) ([]*domain.Credential, error) {
	rows, err := r.executor(ctx).Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Credential
	for rows.Next() {
		c := &domain.Credential{}
		var transports []byte
		if err := rows.Scan(&c.ID, &c.IdentityID, &c.CredentialID, &c.PublicKey, &c.Attestation, &c.AAGUID,
			&c.SignCount, &transports, &c.UserHandle, &c.Label, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(transports, &c.Transports)
		out = append(out, c)
	}
	return out, rows.Err()
}
