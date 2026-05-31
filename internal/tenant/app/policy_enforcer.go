package app

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/krishnaditya65/Project-Janus/internal/tenant/domain"
)

var (
	ErrPasswordTooShort      = errors.New("password too short")
	ErrPasswordNeedsUpper    = errors.New("password requires uppercase letter")
	ErrPasswordNeedsDigit    = errors.New("password requires digit")
	ErrPasswordNeedsSymbol   = errors.New("password requires symbol")
	ErrEmailDomainNotAllowed = errors.New("email domain not allowed")
)

type PolicyEnforcer struct {
	repo domain.PolicyRepository
}

func NewPolicyEnforcer(repo domain.PolicyRepository) *PolicyEnforcer {
	return &PolicyEnforcer{repo: repo}
}

// Get returns the effective policy for the tenant (never nil).
func (e *PolicyEnforcer) Get(ctx context.Context, tenantID string) (*domain.Policy, error) {
	if e == nil || e.repo == nil {
		return domain.DefaultPolicy(), nil
	}
	return e.repo.Get(ctx, tenantID)
}

// ValidatePassword applies password rules from the tenant policy.
func (e *PolicyEnforcer) ValidatePassword(p *domain.Policy, password string) error {
	if p == nil {
		p = domain.DefaultPolicy()
	}
	if len(password) < p.PasswordMinLength {
		return ErrPasswordTooShort
	}
	if p.PasswordRequireUpper && !hasMatch(password, unicode.IsUpper) {
		return ErrPasswordNeedsUpper
	}
	if p.PasswordRequireDigit && !hasMatch(password, unicode.IsDigit) {
		return ErrPasswordNeedsDigit
	}
	if p.PasswordRequireSymbol && !hasMatch(password, isSymbol) {
		return ErrPasswordNeedsSymbol
	}
	return nil
}

// ValidateEmailDomain returns nil if the email's domain is allowed, or
// ErrEmailDomainNotAllowed otherwise. Empty allowlist = allow all.
func (e *PolicyEnforcer) ValidateEmailDomain(p *domain.Policy, email string) error {
	if p == nil || len(p.AllowedEmailDomains) == 0 {
		return nil
	}
	at := strings.LastIndex(email, "@")
	if at == -1 || at == len(email)-1 {
		return ErrEmailDomainNotAllowed
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range p.AllowedEmailDomains {
		if strings.ToLower(d) == domain {
			return nil
		}
	}
	return ErrEmailDomainNotAllowed
}

func hasMatch(s string, f func(rune) bool) bool {
	for _, r := range s {
		if f(r) {
			return true
		}
	}
	return false
}

func isSymbol(r rune) bool {
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}
