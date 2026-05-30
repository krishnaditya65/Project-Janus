package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	pgtx "github.com/krishnaditya65/auth-server/internal/platform/postgres/tx"
	sessiondomain "github.com/krishnaditya65/auth-server/internal/session/domain"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(
	ctx context.Context,
	session *sessiondomain.Session,
) error {

	query := `
		INSERT INTO sessions (
			id,
			tenant_id,
			identity_id,
			user_id,
			refresh_token_hash,
			parent_session_id,
			ip_address,
			user_agent,
			expires_at,
			revoked_at,
			created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`

	_, err := r.executor(ctx).Exec(
		ctx,
		query,
		session.ID,
		session.TenantID,
		session.IdentityID,
		session.UserID,
		session.RefreshTokenHash,
		session.ParentSessionID,
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
		session.RevokedAt,
		session.CreatedAt,
	)

	return err
}

func (r *Repository) GetByID(
	ctx context.Context,
	id string,
) (*sessiondomain.Session, error) {

	query := `
		SELECT
			id,
			tenant_id,
			identity_id,
			user_id,
			refresh_token_hash,
			parent_session_id,
			ip_address::text,
			user_agent,
			expires_at,
			revoked_at,
			created_at
		FROM sessions
		WHERE id = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, id)

	var session sessiondomain.Session

	err := row.Scan(
		&session.ID,
		&session.TenantID,
		&session.IdentityID,
		&session.UserID,
		&session.RefreshTokenHash,
		&session.ParentSessionID,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (r *Repository) GetByRefreshTokenHash(
	ctx context.Context,
	hash string,
) (*sessiondomain.Session, error) {

	query := `
		SELECT
			id,
			tenant_id,
			identity_id,
			user_id,
			refresh_token_hash,
			parent_session_id,
			ip_address::text,
			user_agent,
			expires_at,
			revoked_at,
			created_at
		FROM sessions
		WHERE refresh_token_hash = $1
	`

	row := r.executor(ctx).QueryRow(ctx, query, hash)

	var session sessiondomain.Session

	err := row.Scan(
		&session.ID,
		&session.TenantID,
		&session.IdentityID,
		&session.UserID,
		&session.RefreshTokenHash,
		&session.ParentSessionID,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (r *Repository) Revoke(
	ctx context.Context,
	id string,
) error {

	query := `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE id = $1
	`

	_, err := r.executor(ctx).Exec(ctx, query, id)

	return err
}

func (r *Repository) DeleteExpiredOrRevoked(ctx context.Context, olderThan time.Time) (int64, error) {
	const q = `
		DELETE FROM sessions
		WHERE (expires_at < $1) OR (revoked_at IS NOT NULL AND revoked_at < $1)
	`
	tag, err := r.executor(ctx).Exec(ctx, q, olderThan)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *Repository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}
