package domain

import "context"

// Policy is the per-tenant override layer. Zero value = system defaults.
type Policy struct {
	TenantID              string
	PasswordMinLength     int
	PasswordRequireUpper  bool
	PasswordRequireDigit  bool
	PasswordRequireSymbol bool
	AllowedEmailDomains   []string // empty = any
	RequireMFA            bool
	MaxActiveSessions     int // 0 = unlimited
}

// DefaultPolicy returns the system defaults used when a tenant has no row.
func DefaultPolicy() *Policy {
	return &Policy{
		PasswordMinLength: 8,
	}
}

type PolicyRepository interface {
	Get(ctx context.Context, tenantID string) (*Policy, error)
	Upsert(ctx context.Context, p *Policy) error
}
