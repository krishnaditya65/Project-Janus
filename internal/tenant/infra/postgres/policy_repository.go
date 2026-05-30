package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pgtx "github.com/krishnaditya65/auth-server/internal/platform/postgres/tx"
	"github.com/krishnaditya65/auth-server/internal/tenant/domain"
)

type PolicyRepository struct {
	db *pgxpool.Pool
}

func NewPolicyRepository(db *pgxpool.Pool) *PolicyRepository {
	return &PolicyRepository{db: db}
}

func (r *PolicyRepository) executor(ctx context.Context) pgtx.Executor {
	if tx, ok := pgtx.FromContext(ctx); ok {
		return tx
	}
	return r.db
}

// Get returns the tenant's policy, or DefaultPolicy() with the tenant ID set
// when no row exists. The contract: callers never get nil.
func (r *PolicyRepository) Get(ctx context.Context, tenantID string) (*domain.Policy, error) {
	const q = `
		SELECT password_min_length, password_require_upper, password_require_digit,
			password_require_symbol, allowed_email_domains, require_mfa, max_active_sessions
		FROM tenant_policies WHERE tenant_id = $1`

	row := r.executor(ctx).QueryRow(ctx, q, tenantID)
	p := &domain.Policy{TenantID: tenantID}
	var domains []byte
	err := row.Scan(&p.PasswordMinLength, &p.PasswordRequireUpper, &p.PasswordRequireDigit,
		&p.PasswordRequireSymbol, &domains, &p.RequireMFA, &p.MaxActiveSessions)
	if errors.Is(err, pgx.ErrNoRows) {
		d := domain.DefaultPolicy()
		d.TenantID = tenantID
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	if len(domains) > 0 {
		_ = json.Unmarshal(domains, &p.AllowedEmailDomains)
	}
	return p, nil
}

func (r *PolicyRepository) Upsert(ctx context.Context, p *domain.Policy) error {
	domains, _ := json.Marshal(p.AllowedEmailDomains)
	if len(p.AllowedEmailDomains) == 0 {
		domains = []byte("[]")
	}
	const q = `
		INSERT INTO tenant_policies (tenant_id, password_min_length, password_require_upper,
			password_require_digit, password_require_symbol, allowed_email_domains,
			require_mfa, max_active_sessions, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			password_min_length = EXCLUDED.password_min_length,
			password_require_upper = EXCLUDED.password_require_upper,
			password_require_digit = EXCLUDED.password_require_digit,
			password_require_symbol = EXCLUDED.password_require_symbol,
			allowed_email_domains = EXCLUDED.allowed_email_domains,
			require_mfa = EXCLUDED.require_mfa,
			max_active_sessions = EXCLUDED.max_active_sessions,
			updated_at = NOW()`
	_, err := r.executor(ctx).Exec(ctx, q,
		p.TenantID, p.PasswordMinLength, p.PasswordRequireUpper,
		p.PasswordRequireDigit, p.PasswordRequireSymbol, domains,
		p.RequireMFA, p.MaxActiveSessions)
	return err
}
