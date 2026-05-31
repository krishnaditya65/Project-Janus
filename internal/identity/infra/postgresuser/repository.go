package postgresuser

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
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
	user *identitydomain.User,
) error {

	query := `
		INSERT INTO users (
			id,
			tenant_id,
			identity_id,
			username,
			display_name,
			status,
			created_at,
			updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`

	_, err := r.executor(ctx).Exec(
		ctx,
		query,
		user.ID,
		user.TenantID,
		user.IdentityID,
		user.Username,
		user.DisplayName,
		user.Status,
		user.CreatedAt,
		user.UpdatedAt,
	)

	return err
}

func (r *Repository) GetByID(
	ctx context.Context,
	id string,
) (*identitydomain.User, error) {

	query := `
		SELECT
			id,
			tenant_id,
			identity_id,
			username,
			display_name,
			status,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, id)

	var user identitydomain.User

	err := row.Scan(
		&user.ID,
		&user.TenantID,
		&user.IdentityID,
		&user.Username,
		&user.DisplayName,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *Repository) GetByTenantAndIdentity(
	ctx context.Context,
	tenantID string,
	identityID string,
) (*identitydomain.User, error) {

	query := `
		SELECT
			id,
			tenant_id,
			identity_id,
			username,
			display_name,
			status,
			created_at,
			updated_at
		FROM users
		WHERE tenant_id = $1
		  AND identity_id = $2
	`

	row := r.executor(ctx).QueryRow(ctx, query, tenantID, identityID)

	var user identitydomain.User

	err := row.Scan(
		&user.ID,
		&user.TenantID,
		&user.IdentityID,
		&user.Username,
		&user.DisplayName,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *Repository) GetByIdentityID(
	ctx context.Context,
	identityID string,
) (*identitydomain.User, error) {

	query := `
		SELECT
			id,
			tenant_id,
			identity_id,
			username,
			display_name,
			status,
			created_at,
			updated_at
		FROM users
		WHERE identity_id = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, identityID)

	var user identitydomain.User

	err := row.Scan(
		&user.ID,
		&user.TenantID,
		&user.IdentityID,
		&user.Username,
		&user.DisplayName,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *Repository) GetByTenantAndID(
	ctx context.Context,
	tenantID string,
	userID string,
) (*identitydomain.User, error) {

	query := `
		SELECT
			id,
			tenant_id,
			identity_id,
			username,
			display_name,
			status,
			created_at,
			updated_at
		FROM users
		WHERE tenant_id = $1
		  AND id = $2
	`

	row := r.executor(ctx).QueryRow(ctx, query, tenantID, userID)

	var user identitydomain.User

	err := row.Scan(
		&user.ID,
		&user.TenantID,
		&user.IdentityID,
		&user.Username,
		&user.DisplayName,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *Repository) ListByTenant(
	ctx context.Context,
	tenantID string,
) ([]*identitydomain.User, error) {

	query := `
		SELECT
			id,
			tenant_id,
			identity_id,
			username,
			display_name,
			status,
			created_at,
			updated_at
		FROM users
		WHERE tenant_id = $1
		ORDER BY created_at
	`

	rows, err := r.executor(ctx).Query(ctx, query, tenantID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var users []*identitydomain.User

	for rows.Next() {

		var user identitydomain.User

		err := rows.Scan(
			&user.ID,
			&user.TenantID,
			&user.IdentityID,
			&user.Username,
			&user.DisplayName,
			&user.Status,
			&user.CreatedAt,
			&user.UpdatedAt,
		)

		if err != nil {
			return nil, err
		}

		users = append(users, &user)
	}

	return users, nil
}

func (r *Repository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}
