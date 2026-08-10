package app

import (
	"context"
	"net/http"
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

type LoginResult struct {
	SessionID    string   `json:"session_id"`
	TenantID     string   `json:"tenant_id"`
	UserID       string   `json:"user_id"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
	AccessToken  string   `json:"access_token"`
	ExpiresIn    int      `json:"expires_in"`
	RefreshToken string   `json:"refresh_token"`
}

type LoginUseCase struct {
	service            *Service
	sessionRepo        sessiondomain.Repository
	identityRepo       identitydomain.Repository
	userRepo           identitydomain.UserRepository
	userRoleRepo       authorizationdomain.UserRoleRepository
	rolePermissionRepo authorizationdomain.RolePermissionRepository
	jwtService         *tokenapp.JWTService
}

func NewLoginUseCase(
	service *Service,
	sessionRepo sessiondomain.Repository,
	identityRepo identitydomain.Repository,
	userRepo identitydomain.UserRepository,
	userRoleRepo authorizationdomain.UserRoleRepository,
	rolePermissionRepo authorizationdomain.RolePermissionRepository,
	jwtService *tokenapp.JWTService,
) *LoginUseCase {
	return &LoginUseCase{
		service:            service,
		sessionRepo:        sessionRepo,
		identityRepo:       identityRepo,
		userRepo:           userRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		jwtService:         jwtService,
	}
}

func (u *LoginUseCase) Complete(ctx context.Context, sessionKey string, r *http.Request) (*LoginResult, error) {
	cred, err := u.service.FinishLogin(ctx, sessionKey, r)
	if err != nil {
		return nil, err
	}

	identity, err := u.identityRepo.GetByID(ctx, cred.IdentityID)
	if err != nil {
		return nil, err
	}
	user, err := u.userRepo.GetByIdentityID(ctx, cred.IdentityID)
	if err != nil {
		return nil, err
	}
	roles, err := u.userRoleRepo.GetRolesForUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	permissions, err := u.rolePermissionRepo.GetPermissionsForUser(ctx, user.ID)
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
		TenantID:         user.TenantID,
		IdentityID:       cred.IdentityID,
		UserID:           user.ID,
		RefreshTokenHash: sharedtoken.Hash(refreshToken),
		UserAgent:        r.UserAgent(),
		ExpiresAt:        now.Add(refreshTokenTTL),
		CreatedAt:        now,
	}
	if err := u.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	authPrincipal := &principal.Principal{
		SessionID:   session.ID,
		IdentityID:  cred.IdentityID,
		TenantID:    user.TenantID,
		UserID:      user.ID,
		Email:       identity.PrimaryEmail,
		Roles:       roles,
		Permissions: permissions,
	}

	accessToken, err := u.jwtService.Issue(ctx, authPrincipal, tokenapp.IssueOptions{TTL: accessTokenTTL})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		SessionID:    session.ID,
		TenantID:     user.TenantID,
		UserID:       user.ID,
		Roles:        roles,
		Permissions:  permissions,
		AccessToken:  accessToken,
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
	}, nil
}
