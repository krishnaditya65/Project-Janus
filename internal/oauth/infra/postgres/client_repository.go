package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/krishnaditya65/Project-Janus/internal/oauth/domain"
	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

type ClientRepository struct {
	db *pgxpool.Pool
}

func NewClientRepository(db *pgxpool.Pool) *ClientRepository {
	return &ClientRepository{db: db}
}

func (r *ClientRepository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}

func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	const q = `
		SELECT id, tenant_id, client_id, client_secret_hash, client_name,
			redirect_uris, grant_types, scopes, confidential, created_at
		FROM oauth_clients
		WHERE client_id = $1`

	row := r.executor(ctx).QueryRow(ctx, q, clientID)
	c := &domain.Client{}
	var secret *string
	var redirects, grants, scopes []byte
	err := row.Scan(&c.ID, &c.TenantID, &c.ClientID, &secret, &c.ClientName,
		&redirects, &grants, &scopes, &c.Confidential, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if secret != nil {
		c.ClientSecretHash = *secret
	}
	if err := json.Unmarshal(redirects, &c.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(grants, &c.GrantTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopes, &c.Scopes); err != nil {
		return nil, err
	}
	return c, nil
}

func (r *ClientRepository) Create(ctx context.Context, c *domain.Client) error {
	const q = `
		INSERT INTO oauth_clients (id, tenant_id, client_id, client_secret_hash, client_name,
			redirect_uris, grant_types, scopes, confidential, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	redirects, _ := json.Marshal(c.RedirectURIs)
	grants, _ := json.Marshal(c.GrantTypes)
	scopes, _ := json.Marshal(c.Scopes)

	var secret any
	if c.ClientSecretHash != "" {
		secret = c.ClientSecretHash
	}

	_, err := r.executor(ctx).Exec(ctx, q, c.ID, c.TenantID, c.ClientID, secret, c.ClientName,
		redirects, grants, scopes, c.Confidential, c.CreatedAt)
	return err
}
