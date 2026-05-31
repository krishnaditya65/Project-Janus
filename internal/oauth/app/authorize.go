package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/krishnaditya65/Project-Janus/internal/oauth/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
	sharedtoken "github.com/krishnaditya65/Project-Janus/internal/shared/token"
)

var (
	ErrInvalidClient        = errors.New("invalid_client")
	ErrInvalidRedirectURI   = errors.New("invalid_redirect_uri")
	ErrUnsupportedResponse  = errors.New("unsupported_response_type")
	ErrInvalidScope         = errors.New("invalid_scope")
	ErrMissingPKCE          = errors.New("missing_pkce")
	ErrUnsupportedChallenge = errors.New("unsupported_challenge_method")
	ErrInvalidGrant         = errors.New("invalid_grant")
	ErrUnsupportedGrant     = errors.New("unsupported_grant_type")
)

const codeTTL = 10 * time.Minute

type AuthorizeInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Principal           *principal.Principal
}

type AuthorizeOutput struct {
	Code        string
	State       string
	RedirectURI string
}

type AuthorizeUseCase struct {
	clientRepo domain.ClientRepository
	codeStore  domain.CodeStore
}

func NewAuthorizeUseCase(clientRepo domain.ClientRepository, codeStore domain.CodeStore) *AuthorizeUseCase {
	return &AuthorizeUseCase{clientRepo: clientRepo, codeStore: codeStore}
}

func (u *AuthorizeUseCase) Execute(ctx context.Context, in AuthorizeInput) (*AuthorizeOutput, error) {
	if in.ResponseType != "code" {
		return nil, ErrUnsupportedResponse
	}
	if in.CodeChallenge == "" {
		return nil, ErrMissingPKCE
	}
	if in.CodeChallengeMethod != "S256" {
		return nil, ErrUnsupportedChallenge
	}

	client, err := u.clientRepo.GetByClientID(ctx, in.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if !client.HasRedirectURI(in.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}
	if !client.HasGrantType("authorization_code") {
		return nil, ErrUnsupportedGrant
	}

	requestedScopes := splitScopes(in.Scope)
	for _, s := range requestedScopes {
		if !client.AllowsScope(s) {
			return nil, ErrInvalidScope
		}
	}

	if client.TenantID != in.Principal.TenantID {
		return nil, ErrInvalidClient
	}

	codeStr, err := sharedtoken.GenerateRandom(32)
	if err != nil {
		return nil, err
	}

	code := &domain.AuthorizationCode{
		Code:                codeStr,
		ClientID:            client.ClientID,
		TenantID:            client.TenantID,
		IdentityID:          in.Principal.IdentityID,
		UserID:              in.Principal.UserID,
		Scopes:              requestedScopes,
		RedirectURI:         in.RedirectURI,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		Nonce:               in.Nonce,
		ExpiresAt:           time.Now().UTC().Add(codeTTL),
	}

	if err := u.codeStore.Store(ctx, code); err != nil {
		return nil, err
	}

	return &AuthorizeOutput{
		Code:        codeStr,
		State:       in.State,
		RedirectURI: in.RedirectURI,
	}, nil
}

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	return parts
}
