package app

import (
	"context"
	"time"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	sessiondomain "github.com/krishnaditya65/Project-Janus/internal/session/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
	sharedtoken "github.com/krishnaditya65/Project-Janus/internal/shared/token"
	tokenapp "github.com/krishnaditya65/Project-Janus/internal/token/app"
)

const accessTokenTTL = 15 * time.Minute
const refreshTokenTTL = 7 * 24 * time.Hour

type CompleteInput struct {
	MFAToken string
	Code     string
}

type CompleteOutput struct {
	SessionID    string   `json:"session_id"`
	TenantID     string   `json:"tenant_id"`
	UserID       string   `json:"user_id"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
	AccessToken  string   `json:"access_token"`
	ExpiresIn    int      `json:"expires_in"`
	RefreshToken string   `json:"refresh_token"`
}

type CompleteUseCase struct {
	challengeStore     *ChallengeStore
	totpService        *TOTPService
	sessionRepo        sessiondomain.Repository
	identityRepo       identitydomain.Repository
	userRoleRepo       authorizationdomain.UserRoleRepository
	rolePermissionRepo authorizationdomain.RolePermissionRepository
	jwtService         *tokenapp.JWTService
}

func NewCompleteUseCase(
	challengeStore *ChallengeStore,
	totpService *TOTPService,
	sessionRepo sessiondomain.Repository,
	identityRepo identitydomain.Repository,
	userRoleRepo authorizationdomain.UserRoleRepository,
	rolePermissionRepo authorizationdomain.RolePermissionRepository,
	jwtService *tokenapp.JWTService,
) *CompleteUseCase {
	return &CompleteUseCase{
		challengeStore:     challengeStore,
		totpService:        totpService,
		sessionRepo:        sessionRepo,
		identityRepo:       identityRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		jwtService:         jwtService,
	}
}

func (u *CompleteUseCase) Execute(ctx context.Context, in CompleteInput) (*CompleteOutput, error) {
	challenge, err := u.challengeStore.Consume(ctx, in.MFAToken)
	if err != nil {
		return nil, ErrInvalidCode
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		return nil, ErrInvalidCode
	}

	if err := u.totpService.Verify(ctx, challenge.IdentityID, in.Code); err != nil {
		return nil, ErrInvalidCode
	}

	identity, err := u.identityRepo.GetByID(ctx, challenge.IdentityID)
	if err != nil {
		return nil, err
	}
	roles, err := u.userRoleRepo.GetRolesForUser(ctx, challenge.UserID)
	if err != nil {
		return nil, err
	}
	permissions, err := u.rolePermissionRepo.GetPermissionsForUser(ctx, challenge.UserID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := sharedtoken.GenerateRandom(32)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	ip := challenge.IPAddress
	session := &sessiondomain.Session{
		ID:               id.New(),
		TenantID:         challenge.TenantID,
		IdentityID:       challenge.IdentityID,
		UserID:           challenge.UserID,
		RefreshTokenHash: sharedtoken.Hash(refreshToken),
		IPAddress:        &ip,
		UserAgent:        challenge.UserAgent,
		ExpiresAt:        now.Add(refreshTokenTTL),
		CreatedAt:        now,
	}
	if err := u.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	p := &principal.Principal{
		SessionID:   session.ID,
		IdentityID:  challenge.IdentityID,
		TenantID:    challenge.TenantID,
		UserID:      challenge.UserID,
		Email:       identity.PrimaryEmail,
		Roles:       roles,
		Permissions: permissions,
	}

	accessToken, err := u.jwtService.Issue(ctx, p, tokenapp.IssueOptions{TTL: accessTokenTTL})
	if err != nil {
		return nil, err
	}

	return &CompleteOutput{
		SessionID:    session.ID,
		TenantID:     session.TenantID,
		UserID:       session.UserID,
		Roles:        roles,
		Permissions:  permissions,
		AccessToken:  accessToken,
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
	}, nil
}
