package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
)

type UserRoleRepository struct {
	db *pgxpool.Pool
}

func NewUserRoleRepository(db *pgxpool.Pool) *UserRoleRepository {
	return &UserRoleRepository{db: db}
}

func (r *UserRoleRepository) AssignRole(
	ctx context.Context,
	userRole *authdomain.UserRole,
) error {

	query := `
		INSERT INTO user_roles (
			user_id,
			role_id
		)
		VALUES ($1,$2)
	`

	_, err := r.executor(ctx).Exec(ctx, query,
		userRole.UserID,
		userRole.RoleID,
	)

	return err
}

func (r *UserRoleRepository) GetRolesForUser(
	ctx context.Context,
	userID string,
) ([]string, error) {

	query := `
		SELECT r.name
		FROM user_roles ur
		JOIN roles r
			ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`

	rows, err := r.executor(ctx).Query(ctx, query, userID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var roles []string

	for rows.Next() {
		var role string

		err := rows.Scan(&role)

		if err != nil {
			return nil, err
		}

		roles = append(roles, role)
	}

	return roles, nil
}

func (r *UserRoleRepository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}
