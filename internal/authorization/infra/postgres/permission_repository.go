package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
)

type PermissionRepository struct {
	db *pgxpool.Pool
}

func NewPermissionRepository(db *pgxpool.Pool) *PermissionRepository {
	return &PermissionRepository{db: db}
}

func (r *PermissionRepository) Create(
	ctx context.Context,
	permission *authdomain.Permission,
) error {

	query := `
		INSERT INTO permissions (
			id,
			name,
			description,
			created_at
		)
		VALUES ($1,$2,$3,$4)
	`

	_, err := r.executor(ctx).Exec(ctx, query,
		permission.ID,
		permission.Name,
		permission.Description,
		permission.CreatedAt,
	)

	return err
}

func (r *PermissionRepository) GetByID(
	ctx context.Context,
	id string,
) (*authdomain.Permission, error) {

	query := `
		SELECT
			id,
			name,
			description,
			created_at
		FROM permissions
		WHERE id = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, id)

	var permission authdomain.Permission

	err := row.Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (r *PermissionRepository) GetByName(
	ctx context.Context,
	name string,
) (*authdomain.Permission, error) {

	query := `
		SELECT
			id,
			name,
			description,
			created_at
		FROM permissions
		WHERE name = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, name)

	var permission authdomain.Permission

	err := row.Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (r *PermissionRepository) List(
	ctx context.Context,
) ([]*authdomain.Permission, error) {

	query := `
		SELECT
			id,
			name,
			description,
			created_at
		FROM permissions
		ORDER BY name
	`

	rows, err := r.executor(ctx).Query(ctx, query)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var permissions []*authdomain.Permission

	for rows.Next() {

		var permission authdomain.Permission

		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Description,
			&permission.CreatedAt,
		)

		if err != nil {
			return nil, err
		}

		permissions = append(permissions, &permission)
	}

	return permissions, nil
}

func (r *PermissionRepository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}
