package app

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/krishnaditya65/Project-Janus/internal/mfa/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
)

var (
	ErrInvalidCode    = errors.New("invalid code")
	ErrFactorNotFound = errors.New("factor not found")
)

type TOTPService struct {
	repo   domain.Repository
	issuer string
}

func NewTOTPService(repo domain.Repository, issuer string) *TOTPService {
	return &TOTPService{repo: repo, issuer: issuer}
}

type EnrollmentResult struct {
	FactorID string `json:"factor_id"`
	Secret   string `json:"secret"`
	QRURL    string `json:"qr_url"`
}

func (s *TOTPService) Enroll(ctx context.Context, identityID, email, label string) (*EnrollmentResult, error) {
	if label == "" {
		label = "Authenticator"
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}

	factor := &domain.Factor{
		ID:              id.New(),
		IdentityID:      identityID,
		FactorType:      "totp",
		SecretEncrypted: key.Secret(),
		Label:           label,
		Verified:        false,
		CreatedAt:       time.Now().UTC(),
	}
	if err := s.repo.Create(ctx, factor); err != nil {
		return nil, err
	}

	qrURL := buildOtpauthURL(s.issuer, email, key.Secret())
	return &EnrollmentResult{
		FactorID: factor.ID,
		Secret:   key.Secret(),
		QRURL:    qrURL,
	}, nil
}

func (s *TOTPService) VerifyEnrollment(ctx context.Context, factorID, code string) error {
	factor, err := s.repo.GetByID(ctx, factorID)
	if err != nil {
		return ErrFactorNotFound
	}
	if !totp.Validate(code, factor.SecretEncrypted) {
		return ErrInvalidCode
	}
	return s.repo.MarkVerified(ctx, factor.ID)
}

func (s *TOTPService) Verify(ctx context.Context, identityID, code string) error {
	factors, err := s.repo.GetVerifiedByIdentity(ctx, identityID)
	if err != nil {
		return err
	}
	for _, f := range factors {
		if f.FactorType != "totp" {
			continue
		}
		if totp.Validate(code, f.SecretEncrypted) {
			return nil
		}
	}
	return ErrInvalidCode
}

func (s *TOTPService) Unenroll(ctx context.Context, factorID string) error {
	return s.repo.Delete(ctx, factorID)
}

func (s *TOTPService) List(ctx context.Context, identityID string) ([]*domain.Factor, error) {
	return s.repo.GetByIdentity(ctx, identityID)
}

func buildOtpauthURL(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}
