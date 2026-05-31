package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/krishnaditya65/Project-Janus/internal/mfa/domain"
	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
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

func (r *Repository) Create(ctx context.Context, f *domain.Factor) error {
	const q = `
		INSERT INTO mfa_factors (id, identity_id, factor_type, secret_encrypted, label, verified, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.executor(ctx).Exec(ctx, q, f.ID, f.IdentityID, f.FactorType, f.SecretEncrypted, f.Label, f.Verified, f.CreatedAt)
	return err
}

func (r *Repository) GetByID(ctx context.Context, id string) (*domain.Factor, error) {
	const q = `
		SELECT id, identity_id, factor_type, COALESCE(secret_encrypted, ''), COALESCE(label, ''), verified, created_at
		FROM mfa_factors WHERE id = $1`
	row := r.executor(ctx).QueryRow(ctx, q, id)
	f := &domain.Factor{}
	err := row.Scan(&f.ID, &f.IdentityID, &f.FactorType, &f.SecretEncrypted, &f.Label, &f.Verified, &f.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (r *Repository) GetByIdentity(ctx context.Context, identityID string) ([]*domain.Factor, error) {
	return r.list(ctx, `
		SELECT id, identity_id, factor_type, COALESCE(secret_encrypted, ''), COALESCE(label, ''), verified, created_at
		FROM mfa_factors WHERE identity_id = $1 ORDER BY created_at DESC`, identityID)
}

func (r *Repository) GetVerifiedByIdentity(ctx context.Context, identityID string) ([]*domain.Factor, error) {
	return r.list(ctx, `
		SELECT id, identity_id, factor_type, COALESCE(secret_encrypted, ''), COALESCE(label, ''), verified, created_at
		FROM mfa_factors WHERE identity_id = $1 AND verified = true ORDER BY created_at DESC`, identityID)
}

func (r *Repository) list(ctx context.Context, q string, args ...any) ([]*domain.Factor, error) {
	rows, err := r.executor(ctx).Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Factor
	for rows.Next() {
		f := &domain.Factor{}
		if err := rows.Scan(&f.ID, &f.IdentityID, &f.FactorType, &f.SecretEncrypted, &f.Label, &f.Verified, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *Repository) MarkVerified(ctx context.Context, id string) error {
	_, err := r.executor(ctx).Exec(ctx, `UPDATE mfa_factors SET verified = true WHERE id = $1`, id)
	return err
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	_, err := r.executor(ctx).Exec(ctx, `DELETE FROM mfa_factors WHERE id = $1`, id)
	return err
}
