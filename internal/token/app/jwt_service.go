package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
	"github.com/krishnaditya65/Project-Janus/internal/token/domain"
)

type JWTService struct {
	keyRepo domain.Repository
	issuer  string
}

func NewJWTService(keyRepo domain.Repository, issuer string) *JWTService {
	return &JWTService{keyRepo: keyRepo, issuer: issuer}
}

type IssueOptions struct {
	Audience []string
	TTL      time.Duration
	Nonce    string
}

func (s *JWTService) Issue(ctx context.Context, p *principal.Principal, opts IssueOptions) (string, error) {
	key, err := s.keyRepo.GetActive(ctx)
	if err != nil {
		return "", fmt.Errorf("no active signing key: %w", err)
	}

	now := time.Now().UTC()
	claims := &domain.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   p.IdentityID,
			Audience:  opts.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(opts.TTL)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		TenantID:    p.TenantID,
		UserID:      p.UserID,
		SessionID:   p.SessionID,
		Email:       p.Email,
		Roles:       p.Roles,
		Permissions: p.Permissions,
		Nonce:       opts.Nonce,
	}

	signer, signingMethod, err := parsePrivateKey(key)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = key.ID

	return token.SignedString(signer)
}

func (s *JWTService) Verify(ctx context.Context, tokenStr string) (*domain.Claims, error) {
	claims := &domain.Claims{}

	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid header")
		}
		key, err := s.keyRepo.GetByID(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("unknown kid: %w", err)
		}
		pub, _, err := parsePublicKey(key)
		if err != nil {
			return nil, err
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256", "RS256"}))

	if err != nil {
		return nil, sharederrors.ErrUnauthorized
	}

	return claims, nil
}

func parsePrivateKey(k *domain.SigningKey) (any, jwt.SigningMethod, error) {
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return nil, nil, errors.New("invalid private key PEM")
	}

	switch k.Algorithm {
	case "ES256":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			pk8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, nil, err
			}
			ec, ok := pk8.(*ecdsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("not an ECDSA key")
			}
			return ec, jwt.SigningMethodES256, nil
		}
		return priv, jwt.SigningMethodES256, nil
	case "RS256":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			pk8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, nil, err
			}
			rs, ok := pk8.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("not an RSA key")
			}
			return rs, jwt.SigningMethodRS256, nil
		}
		return priv, jwt.SigningMethodRS256, nil
	}
	return nil, nil, fmt.Errorf("unsupported algorithm: %s", k.Algorithm)
}

func parsePublicKey(k *domain.SigningKey) (any, jwt.SigningMethod, error) {
	block, _ := pem.Decode([]byte(k.PublicKey))
	if block == nil {
		return nil, nil, errors.New("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	switch k.Algorithm {
	case "ES256":
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("not an ECDSA public key")
		}
		return ec, jwt.SigningMethodES256, nil
	case "RS256":
		rs, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("not an RSA public key")
		}
		return rs, jwt.SigningMethodRS256, nil
	}
	return nil, nil, fmt.Errorf("unsupported algorithm: %s", k.Algorithm)
}
