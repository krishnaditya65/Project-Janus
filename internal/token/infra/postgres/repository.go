package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
	"github.com/krishnaditya65/Project-Janus/internal/token/domain"
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

func (r *Repository) GetActive(ctx context.Context) (*domain.SigningKey, error) {
	const q = `
		SELECT id, algorithm, public_key, private_key, is_active, created_at, rotated_at
		FROM signing_keys
		WHERE is_active = true
		ORDER BY created_at DESC
		LIMIT 1`

	row := r.executor(ctx).QueryRow(ctx, q)
	k := &domain.SigningKey{}
	err := row.Scan(&k.ID, &k.Algorithm, &k.PublicKey, &k.PrivateKey, &k.IsActive, &k.CreatedAt, &k.RotatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (r *Repository) GetByID(ctx context.Context, id string) (*domain.SigningKey, error) {
	const q = `
		SELECT id, algorithm, public_key, private_key, is_active, created_at, rotated_at
		FROM signing_keys
		WHERE id = $1`

	row := r.executor(ctx).QueryRow(ctx, q, id)
	k := &domain.SigningKey{}
	err := row.Scan(&k.ID, &k.Algorithm, &k.PublicKey, &k.PrivateKey, &k.IsActive, &k.CreatedAt, &k.RotatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (r *Repository) Create(ctx context.Context, key *domain.SigningKey) error {
	const q = `
		INSERT INTO signing_keys (id, algorithm, public_key, private_key, is_active, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.executor(ctx).Exec(ctx, q, key.ID, key.Algorithm, key.PublicKey, key.PrivateKey, key.IsActive, key.CreatedAt)
	return err
}

func (r *Repository) DeactivateAll(ctx context.Context) error {
	const q = `UPDATE signing_keys SET is_active = false, rotated_at = NOW() WHERE is_active = true`
	_, err := r.executor(ctx).Exec(ctx, q)
	return err
}

func (r *Repository) ListPublic(ctx context.Context) ([]*domain.SigningKey, error) {
	const q = `
		SELECT id, algorithm, public_key, private_key, is_active, created_at, rotated_at
		FROM signing_keys
		WHERE rotated_at IS NULL OR rotated_at > NOW() - INTERVAL '7 days'
		ORDER BY created_at DESC`

	rows, err := r.executor(ctx).Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*domain.SigningKey
	for rows.Next() {
		k := &domain.SigningKey{}
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PublicKey, &k.PrivateKey, &k.IsActive, &k.CreatedAt, &k.RotatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
