package app

import (
	"context"
	"time"

	authorizationdomain "github.com/krishnaditya65/auth-server/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/auth-server/internal/identity/domain"
	sessiondomain "github.com/krishnaditya65/auth-server/internal/session/domain"
	sharederrors "github.com/krishnaditya65/auth-server/internal/shared/errors"
	"github.com/krishnaditya65/auth-server/internal/shared/id"
	"github.com/krishnaditya65/auth-server/internal/shared/principal"
	sharedtoken "github.com/krishnaditya65/auth-server/internal/shared/token"
	tokenapp "github.com/krishnaditya65/auth-server/internal/token/app"
)

type RefreshInput struct {
	RefreshToken string
}

type RefreshOutput struct {
	SessionID    string   `json:"session_id"`
	TenantID     string   `json:"tenant_id"`
	UserID       string   `json:"user_id"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
	AccessToken  string   `json:"access_token"`
	ExpiresIn    int      `json:"expires_in"`
	RefreshToken string   `json:"refresh_token"`
}

type RefreshUseCase struct {
	sessionRepo        sessiondomain.Repository
	identityRepo       identitydomain.Repository
	userRoleRepo       authorizationdomain.UserRoleRepository
	rolePermissionRepo authorizationdomain.RolePermissionRepository
	jwtService         *tokenapp.JWTService
	invalidator        PrincipalInvalidator
}

func NewRefreshUseCase(
	sessionRepo sessiondomain.Repository,
	identityRepo identitydomain.Repository,
	userRoleRepo authorizationdomain.UserRoleRepository,
	rolePermissionRepo authorizationdomain.RolePermissionRepository,
	jwtService *tokenapp.JWTService,
	invalidator PrincipalInvalidator,
) *RefreshUseCase {
	return &RefreshUseCase{
		sessionRepo:        sessionRepo,
		identityRepo:       identityRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		jwtService:         jwtService,
		invalidator:        invalidator,
	}
}

func (u *RefreshUseCase) Execute(ctx context.Context, input RefreshInput) (*RefreshOutput, error) {
	refreshHash := sharedtoken.Hash(input.RefreshToken)

	session, err := u.sessionRepo.GetByRefreshTokenHash(ctx, refreshHash)
	if err != nil {
		return nil, sharederrors.ErrUnauthorized
	}

	if session.RevokedAt != nil {
		return nil, sharederrors.ErrUnauthorized
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, sharederrors.ErrUnauthorized
	}

	if err := u.sessionRepo.Revoke(ctx, session.ID); err != nil {
		return nil, err
	}
	if u.invalidator != nil {
		u.invalidator.Delete(ctx, session.ID)
	}

	newRefreshToken, err := sharedtoken.GenerateRandom(32)
	if err != nil {
		return nil, err
	}
	newRefreshHash := sharedtoken.Hash(newRefreshToken)

	now := time.Now().UTC()
	parentID := session.ID

	newSession := &sessiondomain.Session{
		ID:               id.New(),
		TenantID:         session.TenantID,
		IdentityID:       session.IdentityID,
		UserID:           session.UserID,
		RefreshTokenHash: newRefreshHash,
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

	p := &principal.Principal{
		SessionID:   newSession.ID,
		IdentityID:  session.IdentityID,
		TenantID:    session.TenantID,
		UserID:      session.UserID,
		Email:       identity.PrimaryEmail,
		Roles:       roles,
		Permissions: permissions,
	}

	accessToken, err := u.jwtService.Issue(ctx, p, tokenapp.IssueOptions{TTL: accessTokenTTL})
	if err != nil {
		return nil, err
	}

	return &RefreshOutput{
		SessionID:    newSession.ID,
		TenantID:     newSession.TenantID,
		UserID:       newSession.UserID,
		Roles:        roles,
		Permissions:  permissions,
		AccessToken:  accessToken,
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		RefreshToken: newRefreshToken,
	}, nil
}
