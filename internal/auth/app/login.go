package app

import (
	"context"
	"errors"
	"time"

	authdomain "github.com/krishnaditya65/auth-server/internal/auth/domain"
	authorizationdomain "github.com/krishnaditya65/auth-server/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/auth-server/internal/identity/domain"
	mfaapp "github.com/krishnaditya65/auth-server/internal/mfa/app"
	mfadomain "github.com/krishnaditya65/auth-server/internal/mfa/domain"
	sessiondomain "github.com/krishnaditya65/auth-server/internal/session/domain"
	sharederrors "github.com/krishnaditya65/auth-server/internal/shared/errors"
	"github.com/krishnaditya65/auth-server/internal/shared/id"
	"github.com/krishnaditya65/auth-server/internal/shared/password"
	"github.com/krishnaditya65/auth-server/internal/shared/principal"
	sharedtoken "github.com/krishnaditya65/auth-server/internal/shared/token"
	tenantapp "github.com/krishnaditya65/auth-server/internal/tenant/app"
	tokenapp "github.com/krishnaditya65/auth-server/internal/token/app"
)

// ErrMFAEnrollmentRequired is returned when the tenant policy mandates MFA
// but the identity has no verified factors.
var ErrMFAEnrollmentRequired = errors.New("mfa enrollment required")

const accessTokenTTL = 15 * time.Minute
const refreshTokenTTL = 7 * 24 * time.Hour

type LoginInput struct {
	Email     string
	Password  string
	IPAddress string
	UserAgent string
}

type LoginOutput struct {
	SessionID    string   `json:"session_id,omitempty"`
	TenantID     string   `json:"tenant_id,omitempty"`
	UserID       string   `json:"user_id,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	AccessToken  string   `json:"access_token,omitempty"`
	ExpiresIn    int      `json:"expires_in,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	MFARequired  bool     `json:"mfa_required,omitempty"`
	MFAToken     string   `json:"mfa_token,omitempty"`
}

type LoginUseCase struct {
	identityRepo       identitydomain.Repository
	credentialRepo     authdomain.Repository
	userRepo           identitydomain.UserRepository
	userRoleRepo       authorizationdomain.UserRoleRepository
	rolePermissionRepo authorizationdomain.RolePermissionRepository
	sessionRepo        sessiondomain.Repository
	jwtService         *tokenapp.JWTService
	mfaRepo            mfadomain.Repository
	mfaChallengeStore  *mfaapp.ChallengeStore
	policyEnforcer     *tenantapp.PolicyEnforcer
}

func NewLoginUseCase(
	identityRepo identitydomain.Repository,
	credentialRepo authdomain.Repository,
	userRepo identitydomain.UserRepository,
	userRoleRepo authorizationdomain.UserRoleRepository,
	rolePermissionRepo authorizationdomain.RolePermissionRepository,
	sessionRepo sessiondomain.Repository,
	jwtService *tokenapp.JWTService,
	mfaRepo mfadomain.Repository,
	mfaChallengeStore *mfaapp.ChallengeStore,
	policyEnforcer *tenantapp.PolicyEnforcer,
) *LoginUseCase {
	return &LoginUseCase{
		identityRepo:       identityRepo,
		credentialRepo:     credentialRepo,
		userRepo:           userRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		sessionRepo:        sessionRepo,
		jwtService:         jwtService,
		mfaRepo:            mfaRepo,
		mfaChallengeStore:  mfaChallengeStore,
		policyEnforcer:     policyEnforcer,
	}
}

func (u *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	identity, err := u.identityRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, sharederrors.ErrInvalidCredentials
	}

	credential, err := u.credentialRepo.GetByIdentityID(ctx, identity.ID)
	if err != nil {
		return nil, sharederrors.ErrInvalidCredentials
	}

	if !password.Verify(input.Password, credential.PasswordHash) {
		return nil, sharederrors.ErrInvalidCredentials
	}

	user, err := u.userRepo.GetByIdentityID(ctx, identity.ID)
	if err != nil {
		return nil, err
	}

	policy, err := u.policyEnforcer.Get(ctx, user.TenantID)
	if err != nil {
		return nil, err
	}

	factors, err := u.mfaRepo.GetVerifiedByIdentity(ctx, identity.ID)
	if err != nil {
		return nil, err
	}
	if policy.RequireMFA && len(factors) == 0 {
		return nil, ErrMFAEnrollmentRequired
	}
	if len(factors) > 0 {
		mfaToken, err := sharedtoken.GenerateRandom(32)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		challenge := &mfaapp.Challenge{
			Token:      mfaToken,
			IdentityID: identity.ID,
			TenantID:   user.TenantID,
			UserID:     user.ID,
			IPAddress:  input.IPAddress,
			UserAgent:  input.UserAgent,
			ExpiresAt:  now.Add(5 * time.Minute),
		}
		if err := u.mfaChallengeStore.Store(ctx, challenge); err != nil {
			return nil, err
		}
		return &LoginOutput{MFARequired: true, MFAToken: mfaToken}, nil
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
	refreshHash := sharedtoken.Hash(refreshToken)

	now := time.Now().UTC()
	ip := input.IPAddress
	session := &sessiondomain.Session{
		ID:               id.New(),
		TenantID:         user.TenantID,
		IdentityID:       identity.ID,
		UserID:           user.ID,
		RefreshTokenHash: refreshHash,
		IPAddress:        &ip,
		UserAgent:        input.UserAgent,
		ExpiresAt:        now.Add(refreshTokenTTL),
		CreatedAt:        now,
	}

	if err := u.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	p := &principal.Principal{
		SessionID:   session.ID,
		IdentityID:  identity.ID,
		TenantID:    user.TenantID,
		UserID:      user.ID,
		Email:       identity.PrimaryEmail,
		Roles:       roles,
		Permissions: permissions,
	}

	accessToken, err := u.jwtService.Issue(ctx, p, tokenapp.IssueOptions{TTL: accessTokenTTL})
	if err != nil {
		return nil, err
	}

	return &LoginOutput{
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
