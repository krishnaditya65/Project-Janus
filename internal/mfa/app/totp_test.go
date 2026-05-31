package app

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/krishnaditya65/Project-Janus/internal/mfa/domain"
)

type memFactorRepo struct {
	factors map[string]*domain.Factor
}

func newMemRepo() *memFactorRepo {
	return &memFactorRepo{factors: map[string]*domain.Factor{}}
}

func (r *memFactorRepo) Create(_ context.Context, f *domain.Factor) error {
	r.factors[f.ID] = f
	return nil
}
func (r *memFactorRepo) GetByID(_ context.Context, id string) (*domain.Factor, error) {
	f, ok := r.factors[id]
	if !ok {
		return nil, context.DeadlineExceeded
	}
	return f, nil
}
func (r *memFactorRepo) GetByIdentity(_ context.Context, identityID string) ([]*domain.Factor, error) {
	var out []*domain.Factor
	for _, f := range r.factors {
		if f.IdentityID == identityID {
			out = append(out, f)
		}
	}
	return out, nil
}
func (r *memFactorRepo) GetVerifiedByIdentity(_ context.Context, identityID string) ([]*domain.Factor, error) {
	var out []*domain.Factor
	for _, f := range r.factors {
		if f.IdentityID == identityID && f.Verified {
			out = append(out, f)
		}
	}
	return out, nil
}
func (r *memFactorRepo) MarkVerified(_ context.Context, id string) error {
	if f, ok := r.factors[id]; ok {
		f.Verified = true
	}
	return nil
}
func (r *memFactorRepo) Delete(_ context.Context, id string) error {
	delete(r.factors, id)
	return nil
}

func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestTOTP_EnrollProducesSecretAndQR(t *testing.T) {
	svc := NewTOTPService(newMemRepo(), "TestIssuer")
	r, err := svc.Enroll(context.Background(), "identity-1", "a@example.com", "My Phone")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if r.Secret == "" || r.QRURL == "" || r.FactorID == "" {
		t.Errorf("missing fields: %+v", r)
	}
	if len(r.Secret) < 16 {
		t.Errorf("secret too short: %d chars", len(r.Secret))
	}
}

func TestTOTP_VerifyEnrollmentMarksVerified(t *testing.T) {
	repo := newMemRepo()
	svc := NewTOTPService(repo, "TestIssuer")
	r, _ := svc.Enroll(context.Background(), "id-1", "a@b.com", "")
	if err := svc.VerifyEnrollment(context.Background(), r.FactorID, currentCode(t, r.Secret)); err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	if !repo.factors[r.FactorID].Verified {
		t.Error("factor should be marked verified")
	}
}

func TestTOTP_VerifyEnrollmentWrongCode(t *testing.T) {
	svc := NewTOTPService(newMemRepo(), "TestIssuer")
	r, _ := svc.Enroll(context.Background(), "id-1", "a@b.com", "")
	if err := svc.VerifyEnrollment(context.Background(), r.FactorID, "000000"); err == nil {
		t.Error("expected error for wrong code")
	}
}

func TestTOTP_VerifyUsesAllVerifiedFactors(t *testing.T) {
	repo := newMemRepo()
	svc := NewTOTPService(repo, "TestIssuer")
	r1, _ := svc.Enroll(context.Background(), "id-1", "a@b.com", "phone")
	r2, _ := svc.Enroll(context.Background(), "id-1", "a@b.com", "key")
	_ = svc.VerifyEnrollment(context.Background(), r1.FactorID, currentCode(t, r1.Secret))
	_ = svc.VerifyEnrollment(context.Background(), r2.FactorID, currentCode(t, r2.Secret))

	if err := svc.Verify(context.Background(), "id-1", currentCode(t, r2.Secret)); err != nil {
		t.Errorf("Verify should accept code from second factor: %v", err)
	}
}

func TestTOTP_VerifyIgnoresUnverified(t *testing.T) {
	repo := newMemRepo()
	svc := NewTOTPService(repo, "TestIssuer")
	r, _ := svc.Enroll(context.Background(), "id-1", "a@b.com", "")
	// do not mark verified
	if err := svc.Verify(context.Background(), "id-1", currentCode(t, r.Secret)); err == nil {
		t.Error("Verify should not consider unverified factors")
	}
}

func TestTOTP_UnenrollDeletes(t *testing.T) {
	repo := newMemRepo()
	svc := NewTOTPService(repo, "TestIssuer")
	r, _ := svc.Enroll(context.Background(), "id-1", "a@b.com", "")
	_ = svc.Unenroll(context.Background(), r.FactorID)
	if _, ok := repo.factors[r.FactorID]; ok {
		t.Error("factor should be deleted")
	}
}
