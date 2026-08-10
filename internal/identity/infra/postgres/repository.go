package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(
	ctx context.Context,
	identity *identitydomain.Identity,
) error {
	query := `
		INSERT INTO identities (
			id,
			primary_email,
			email_verified,
			status,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.executor(ctx).Exec(
		ctx,
		query,
		identity.ID,
		identity.PrimaryEmail,
		identity.EmailVerified,
		identity.Status,
		identity.CreatedAt,
		identity.UpdatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				return sharederrors.ErrConflict
			}
		}
		return err
	}

	return nil
}

func (r *Repository) GetByEmail(
	ctx context.Context,
	email string,
) (*identitydomain.Identity, error) {
	query := `
		SELECT
			id,
			primary_email,
			email_verified,
			status,
			created_at,
			updated_at
		FROM identities
		WHERE primary_email = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, email)

	var identity identitydomain.Identity

	err := row.Scan(
		&identity.ID,
		&identity.PrimaryEmail,
		&identity.EmailVerified,
		&identity.Status,
		&identity.CreatedAt,
		&identity.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &identity, nil
}

func (r *Repository) GetByID(
	ctx context.Context,
	id string,
) (*identitydomain.Identity, error) {
	query := `
		SELECT
			id,
			primary_email,
			email_verified,
			status,
			created_at,
			updated_at
		FROM identities
		WHERE id = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, id)

	var identity identitydomain.Identity

	err := row.Scan(
		&identity.ID,
		&identity.PrimaryEmail,
		&identity.EmailVerified,
		&identity.Status,
		&identity.CreatedAt,
		&identity.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &identity, nil
}

func (r *Repository) Delete(
	ctx context.Context,
	id string,
) error {
	query := `DELETE FROM identities WHERE id = $1`

	_, err := r.executor(ctx).Exec(ctx, query, id)
	if err != nil {
		return err
	}

	return nil
}

func (r *Repository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}
