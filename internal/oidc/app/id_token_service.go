package app

import (
	"context"
	"time"

	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
	tokenapp "github.com/krishnaditya65/Project-Janus/internal/token/app"
)

type IDTokenService struct {
	jwtService *tokenapp.JWTService
}

func NewIDTokenService(jwtService *tokenapp.JWTService) *IDTokenService {
	return &IDTokenService{jwtService: jwtService}
}

func (s *IDTokenService) IssueIDToken(ctx context.Context, p *principal.Principal, clientID, nonce string, ttl time.Duration) (string, error) {
	idPrincipal := &principal.Principal{
		SessionID:  p.SessionID,
		IdentityID: p.IdentityID,
		TenantID:   p.TenantID,
		UserID:     p.UserID,
		Email:      p.Email,
	}

	return s.jwtService.Issue(ctx, idPrincipal, tokenapp.IssueOptions{
		TTL:      ttl,
		Audience: []string{clientID},
		Nonce:    nonce,
	})
}
