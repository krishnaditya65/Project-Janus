package integration

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func dbURL() string {
	if u := os.Getenv("DATABASE_URL"); u != "" {
		return u
	}
	return "postgres://authadmin:authpassword@localhost:5433/authserver?sslmode=disable"
}

var sharedPool *pgxpool.Pool

func pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if sharedPool != nil {
		return sharedPool
	}
	p, err := pgxpool.New(context.Background(), dbURL())
	if err != nil {
		t.Skipf("cannot connect to database: %v", err)
	}
	sharedPool = p
	return p
}

// CreateOAuthClientForTenant inserts a public OAuth client for the given tenant.
// Returns the client_id (which equals the supplied prefix).
func CreateOAuthClientForTenant(t *testing.T, tenantID, clientID string) string {
	t.Helper()
	p := pool(t)
	const q = `
		INSERT INTO oauth_clients (id, tenant_id, client_id, client_name, redirect_uris, grant_types, scopes, confidential)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, false)
		ON CONFLICT (client_id) DO NOTHING`
	_, err := p.Exec(context.Background(), q,
		uuid.NewString(), tenantID, clientID, "Test "+clientID,
		`["http://localhost:3000/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["openid","profile","email"]`)
	if err != nil {
		t.Fatalf("create oauth client: %v", err)
	}
	return clientID
}
