package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
	tenantdomain "github.com/krishnaditya65/Project-Janus/internal/tenant/domain"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(
	ctx context.Context,
	tenant *tenantdomain.Tenant,
) error {
	query := `
		INSERT INTO tenants (
			id,
			slug,
			display_name,
			status,
			created_at,
			updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6)
	`

	_, err := r.executor(ctx).Exec(
		ctx,
		query,
		tenant.ID,
		tenant.Slug,
		tenant.DisplayName,
		tenant.Status,
		tenant.CreatedAt,
		tenant.UpdatedAt,
	)

	return err
}

func (r *Repository) GetByID(
	ctx context.Context,
	id string,
) (*tenantdomain.Tenant, error) {

	query := `
		SELECT
			id,
			slug,
			display_name,
			status,
			created_at,
			updated_at
		FROM tenants
		WHERE id = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, id)

	var tenant tenantdomain.Tenant

	err := row.Scan(
		&tenant.ID,
		&tenant.Slug,
		&tenant.DisplayName,
		&tenant.Status,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &tenant, nil
}

func (r *Repository) GetBySlug(
	ctx context.Context,
	slug string,
) (*tenantdomain.Tenant, error) {

	query := `
		SELECT
			id,
			slug,
			display_name,
			status,
			created_at,
			updated_at
		FROM tenants
		WHERE slug = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, slug)

	var tenant tenantdomain.Tenant

	err := row.Scan(
		&tenant.ID,
		&tenant.Slug,
		&tenant.DisplayName,
		&tenant.Status,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &tenant, nil
}

func (r *Repository) ExistsBySlug(
	ctx context.Context,
	slug string,
) (bool, error) {

	query := `
		SELECT EXISTS(
			SELECT 1
			FROM tenants
			WHERE slug = $1
		)
	`

	var exists bool

	err := r.executor(ctx).QueryRow(ctx, query, slug).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *Repository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}
