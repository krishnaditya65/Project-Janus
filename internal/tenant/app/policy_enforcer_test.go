package app

import (
	"testing"

	"github.com/krishnaditya65/Project-Janus/internal/tenant/domain"
)

func TestValidatePassword_MinLength(t *testing.T) {
	e := NewPolicyEnforcer(nil)
	p := &domain.Policy{PasswordMinLength: 10}
	if err := e.ValidatePassword(p, "short"); err != ErrPasswordTooShort {
		t.Errorf("expected ErrPasswordTooShort, got %v", err)
	}
	if err := e.ValidatePassword(p, "longenough123"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidatePassword_ComplexityRules(t *testing.T) {
	e := NewPolicyEnforcer(nil)
	p := &domain.Policy{
		PasswordMinLength:     6,
		PasswordRequireUpper:  true,
		PasswordRequireDigit:  true,
		PasswordRequireSymbol: true,
	}
	cases := map[string]error{
		"abcdef":   ErrPasswordNeedsUpper,
		"Abcdef":   ErrPasswordNeedsDigit,
		"Abcdef1":  ErrPasswordNeedsSymbol,
		"Abcdef1!": nil,
		"Aa1!!!":   nil,
	}
	for pw, want := range cases {
		if got := e.ValidatePassword(p, pw); got != want {
			t.Errorf("%q: got %v, want %v", pw, got, want)
		}
	}
}

func TestValidateEmailDomain_EmptyAllowlist(t *testing.T) {
	e := NewPolicyEnforcer(nil)
	p := &domain.Policy{}
	if err := e.ValidateEmailDomain(p, "alice@anywhere.com"); err != nil {
		t.Errorf("empty allowlist should allow any domain: %v", err)
	}
}

func TestValidateEmailDomain_AllowedAndDenied(t *testing.T) {
	e := NewPolicyEnforcer(nil)
	p := &domain.Policy{AllowedEmailDomains: []string{"company.com", "Subsidiary.io"}}
	cases := map[string]bool{
		"alice@company.com": true,
		"bob@subsidiary.io": true, // case-insensitive
		"BOB@SUBSIDIARY.IO": true,
		"eve@other.com":     false,
		"no-at-sign":        false,
		"trailing@":         false,
	}
	for email, want := range cases {
		got := e.ValidateEmailDomain(p, email) == nil
		if got != want {
			t.Errorf("%q: allowed=%v, want %v", email, got, want)
		}
	}
}
