package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/auth/domain"
	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(
	ctx context.Context,
	credential *authdomain.Credential,
) error {
	query := `
		INSERT INTO credentials (
			id,
			identity_id,
			credential_type,
			password_hash,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.executor(ctx).Exec(
		ctx,
		query,
		credential.ID,
		credential.IdentityID,
		credential.CredentialType,
		credential.PasswordHash,
		credential.CreatedAt,
		credential.UpdatedAt,
	)

	return err
}

func (r *Repository) GetByIdentityID(
	ctx context.Context,
	identityID string,
) (*authdomain.Credential, error) {
	query := `
		SELECT
			id,
			identity_id,
			credential_type,
			password_hash,
			created_at,
			updated_at
		FROM credentials
		WHERE identity_id = $1
		LIMIT 1
	`

	row := r.executor(ctx).QueryRow(ctx, query, identityID)

	var credential authdomain.Credential

	err := row.Scan(
		&credential.ID,
		&credential.IdentityID,
		&credential.CredentialType,
		&credential.PasswordHash,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &credential, nil
}

func (r *Repository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}
