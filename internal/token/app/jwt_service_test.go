package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/krishnaditya65/auth-server/internal/shared/principal"
	"github.com/krishnaditya65/auth-server/internal/token/domain"
)

type memKeyRepo struct {
	key *domain.SigningKey
}

func (r *memKeyRepo) GetActive(ctx context.Context) (*domain.SigningKey, error) {
	return r.key, nil
}
func (r *memKeyRepo) GetByID(ctx context.Context, id string) (*domain.SigningKey, error) {
	if r.key != nil && r.key.ID == id {
		return r.key, nil
	}
	return nil, context.DeadlineExceeded
}
func (r *memKeyRepo) Create(ctx context.Context, k *domain.SigningKey) error {
	r.key = k
	return nil
}
func (r *memKeyRepo) DeactivateAll(ctx context.Context) error                { return nil }
func (r *memKeyRepo) ListPublic(ctx context.Context) ([]*domain.SigningKey, error) {
	if r.key == nil {
		return nil, nil
	}
	return []*domain.SigningKey{r.key}, nil
}

func freshService(t *testing.T, alg string) *JWTService {
	t.Helper()
	k, err := GenerateKey(alg)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", alg, err)
	}
	repo := &memKeyRepo{key: k}
	return NewJWTService(repo, "https://test.iss")
}

var testPrincipal = &principal.Principal{
	SessionID:   "sid-1",
	IdentityID:  "id-1",
	TenantID:    "tn-1",
	UserID:      "u-1",
	Email:       "a@example.com",
	Roles:       []string{"tenant_owner"},
	Permissions: []string{"users:read"},
}

func TestJWT_IssueAndVerify_ES256(t *testing.T) {
	s := freshService(t, "ES256")
	tok, err := s.Issue(context.Background(), testPrincipal, IssueOptions{TTL: time.Minute})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(tok, "eyJ") {
		t.Errorf("token does not look like JWT: %s", tok)
	}
	claims, err := s.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TenantID != testPrincipal.TenantID {
		t.Errorf("tenant claim mismatch: %s", claims.TenantID)
	}
	if claims.SessionID != testPrincipal.SessionID {
		t.Errorf("session claim mismatch: %s", claims.SessionID)
	}
	if claims.Issuer != "https://test.iss" {
		t.Errorf("issuer mismatch: %s", claims.Issuer)
	}
}

func TestJWT_IssueAndVerify_RS256(t *testing.T) {
	s := freshService(t, "RS256")
	tok, err := s.Issue(context.Background(), testPrincipal, IssueOptions{TTL: time.Minute})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestJWT_RejectsTampered(t *testing.T) {
	s := freshService(t, "ES256")
	tok, _ := s.Issue(context.Background(), testPrincipal, IssueOptions{TTL: time.Minute})
	// Flip a char in the payload section
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal("expected 3 JWT parts")
	}
	tampered := parts[0] + "." + parts[1][:len(parts[1])-1] + "A." + parts[2]
	if _, err := s.Verify(context.Background(), tampered); err == nil {
		t.Error("Verify should reject tampered payload")
	}
}

func TestJWT_RejectsExpired(t *testing.T) {
	s := freshService(t, "ES256")
	tok, _ := s.Issue(context.Background(), testPrincipal, IssueOptions{TTL: -1 * time.Second})
	if _, err := s.Verify(context.Background(), tok); err == nil {
		t.Error("Verify should reject expired token")
	}
}

func TestJWT_RejectsUnknownKID(t *testing.T) {
	s := freshService(t, "ES256")
	tok, _ := s.Issue(context.Background(), testPrincipal, IssueOptions{TTL: time.Minute})
	// Build a service with a different repo: lookup of the original kid fails
	other := NewJWTService(&memKeyRepo{key: nil}, "https://test.iss")
	if _, err := other.Verify(context.Background(), tok); err == nil {
		t.Error("Verify should fail when kid not found")
	}
}

func TestJWT_NonceIncluded(t *testing.T) {
	s := freshService(t, "ES256")
	tok, _ := s.Issue(context.Background(), testPrincipal, IssueOptions{TTL: time.Minute, Nonce: "nonce-xyz"})
	c, err := s.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Nonce != "nonce-xyz" {
		t.Errorf("nonce mismatch: %q", c.Nonce)
	}
}

func TestJWT_AudienceSet(t *testing.T) {
	s := freshService(t, "ES256")
	tok, _ := s.Issue(context.Background(), testPrincipal, IssueOptions{TTL: time.Minute, Audience: []string{"client-1"}})
	c, _ := s.Verify(context.Background(), tok)
	if len(c.Audience) != 1 || c.Audience[0] != "client-1" {
		t.Errorf("audience mismatch: %v", c.Audience)
	}
}

func BenchmarkJWT_Issue(b *testing.B) {
	s := freshService(&testing.T{}, "ES256")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Issue(ctx, testPrincipal, IssueOptions{TTL: time.Minute})
	}
}

func BenchmarkJWT_Verify(b *testing.B) {
	s := freshService(&testing.T{}, "ES256")
	ctx := context.Background()
	tok, _ := s.Issue(ctx, testPrincipal, IssueOptions{TTL: time.Hour})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Verify(ctx, tok)
	}
}
