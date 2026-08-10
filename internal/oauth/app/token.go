package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"time"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	"github.com/krishnaditya65/Project-Janus/internal/oauth/domain"
	sessiondomain "github.com/krishnaditya65/Project-Janus/internal/session/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
	sharedtoken "github.com/krishnaditya65/Project-Janus/internal/shared/token"
	tokenapp "github.com/krishnaditya65/Project-Janus/internal/token/app"
)

const accessTokenTTL = 15 * time.Minute
const refreshTokenTTL = 7 * 24 * time.Hour

type IDTokenIssuer interface {
	IssueIDToken(ctx context.Context, p *principal.Principal, clientID, nonce string, ttl time.Duration) (string, error)
}

type TokenInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

type TokenOutput struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type TokenUseCase struct {
	clientRepo         domain.ClientRepository
	codeStore          domain.CodeStore
	sessionRepo        sessiondomain.Repository
	identityRepo       identitydomain.Repository
	userRoleRepo       authorizationdomain.UserRoleRepository
	rolePermissionRepo authorizationdomain.RolePermissionRepository
	jwtService         *tokenapp.JWTService
	idTokenIssuer      IDTokenIssuer
}

func NewTokenUseCase(
	clientRepo domain.ClientRepository,
	codeStore domain.CodeStore,
	sessionRepo sessiondomain.Repository,
	identityRepo identitydomain.Repository,
	userRoleRepo authorizationdomain.UserRoleRepository,
	rolePermissionRepo authorizationdomain.RolePermissionRepository,
	jwtService *tokenapp.JWTService,
	idTokenIssuer IDTokenIssuer,
) *TokenUseCase {
	return &TokenUseCase{
		clientRepo:         clientRepo,
		codeStore:          codeStore,
		sessionRepo:        sessionRepo,
		identityRepo:       identityRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		jwtService:         jwtService,
		idTokenIssuer:      idTokenIssuer,
	}
}

func (u *TokenUseCase) Execute(ctx context.Context, in TokenInput) (*TokenOutput, error) {
	switch in.GrantType {
	case "authorization_code":
		return u.authorizationCodeGrant(ctx, in)
	case "refresh_token":
		return u.refreshTokenGrant(ctx, in)
	}
	return nil, ErrUnsupportedGrant
}

func (u *TokenUseCase) authorizationCodeGrant(ctx context.Context, in TokenInput) (*TokenOutput, error) {
	client, err := u.clientRepo.GetByClientID(ctx, in.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if client.Confidential {
		if in.ClientSecret == "" {
			return nil, ErrInvalidClient
		}
		expected := sharedtoken.Hash(in.ClientSecret)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(client.ClientSecretHash)) != 1 {
			return nil, ErrInvalidClient
		}
	}

	code, err := u.codeStore.Consume(ctx, in.Code)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if time.Now().UTC().After(code.ExpiresAt) {
		return nil, ErrInvalidGrant
	}
	if code.ClientID != in.ClientID {
		return nil, ErrInvalidGrant
	}
	if code.RedirectURI != in.RedirectURI {
		return nil, ErrInvalidGrant
	}

	if !verifyPKCE(in.CodeVerifier, code.CodeChallenge) {
		return nil, ErrInvalidGrant
	}

	identity, err := u.identityRepo.GetByID(ctx, code.IdentityID)
	if err != nil {
		return nil, err
	}

	roles, err := u.userRoleRepo.GetRolesForUser(ctx, code.UserID)
	if err != nil {
		return nil, err
	}

	permissions, err := u.rolePermissionRepo.GetPermissionsForUser(ctx, code.UserID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := sharedtoken.GenerateRandom(32)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	session := &sessiondomain.Session{
		ID:               id.New(),
		TenantID:         code.TenantID,
		IdentityID:       code.IdentityID,
		UserID:           code.UserID,
		RefreshTokenHash: sharedtoken.Hash(refreshToken),
		ExpiresAt:        now.Add(refreshTokenTTL),
		CreatedAt:        now,
	}
	if err := u.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	authPrincipal := &principal.Principal{
		SessionID:   session.ID,
		IdentityID:  code.IdentityID,
		TenantID:    code.TenantID,
		UserID:      code.UserID,
		Email:       identity.PrimaryEmail,
		Roles:       roles,
		Permissions: permissions,
	}

	accessToken, err := u.jwtService.Issue(ctx, authPrincipal, tokenapp.IssueOptions{
		TTL:      accessTokenTTL,
		Audience: []string{in.ClientID},
	})
	if err != nil {
		return nil, err
	}

	out := &TokenOutput{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        strings.Join(code.Scopes, " "),
	}

	if hasScope(code.Scopes, "openid") && u.idTokenIssuer != nil {
		idToken, err := u.idTokenIssuer.IssueIDToken(ctx, authPrincipal, in.ClientID, code.Nonce, accessTokenTTL)
		if err != nil {
			return nil, err
		}
		out.IDToken = idToken
	}

	return out, nil
}

func (u *TokenUseCase) refreshTokenGrant(ctx context.Context, in TokenInput) (*TokenOutput, error) {
	session, err := u.sessionRepo.GetByRefreshTokenHash(ctx, sharedtoken.Hash(in.RefreshToken))
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if session.RevokedAt != nil || time.Now().UTC().After(session.ExpiresAt) {
		return nil, ErrInvalidGrant
	}

	if err := u.sessionRepo.Revoke(ctx, session.ID); err != nil {
		return nil, err
	}

	newRefreshToken, err := sharedtoken.GenerateRandom(32)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	parentID := session.ID
	newSession := &sessiondomain.Session{
		ID:               id.New(),
		TenantID:         session.TenantID,
		IdentityID:       session.IdentityID,
		UserID:           session.UserID,
		RefreshTokenHash: sharedtoken.Hash(newRefreshToken),
		ParentSessionID:  &parentID,
		IPAddress:        session.IPAddress,
		UserAgent:        session.UserAgent,
		ExpiresAt:        now.Add(refreshTokenTTL),
		CreatedAt:        now,
	}
	if err := u.sessionRepo.Create(ctx, newSession); err != nil {
		return nil, err
	}

	identity, err := u.identityRepo.GetByID(ctx, session.IdentityID)
	if err != nil {
		return nil, err
	}
	roles, err := u.userRoleRepo.GetRolesForUser(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	permissions, err := u.rolePermissionRepo.GetPermissionsForUser(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	authPrincipal := &principal.Principal{
		SessionID:   newSession.ID,
		IdentityID:  session.IdentityID,
		TenantID:    session.TenantID,
		UserID:      session.UserID,
		Email:       identity.PrimaryEmail,
		Roles:       roles,
		Permissions: permissions,
	}

	accessToken, err := u.jwtService.Issue(ctx, authPrincipal, tokenapp.IssueOptions{
		TTL:      accessTokenTTL,
		Audience: []string{in.ClientID},
	})
	if err != nil {
		return nil, err
	}

	return &TokenOutput{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		RefreshToken: newRefreshToken,
	}, nil
}

func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(challenge)) == 1
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
